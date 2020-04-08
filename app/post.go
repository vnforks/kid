// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
	"github.com/vnforks/kid/v5/utils"
)

const (
	PENDING_POST_IDS_CACHE_SIZE = 25000
	PENDING_POST_IDS_CACHE_TTL  = 30 * time.Second
	PAGE_DEFAULT                = 0
)

func (a *App) CreatePostAsUser(post *model.Post, currentSessionId string) (*model.Post, *model.AppError) {
	// Check that class has not been deleted
	class, errCh := a.Srv().Store.Class().Get(post.ClassId, true)
	if errCh != nil {
		err := model.NewAppError("CreatePostAsUser", "api.context.invalid_param.app_error", map[string]interface{}{"Name": "post.class_id"}, errCh.Error(), http.StatusBadRequest)
		return nil, err
	}

	if strings.HasPrefix(post.Type, model.POST_SYSTEM_MESSAGE_PREFIX) {
		err := model.NewAppError("CreatePostAsUser", "api.context.invalid_param.app_error", map[string]interface{}{"Name": "post.type"}, "", http.StatusBadRequest)
		return nil, err
	}

	if class.DeleteAt != 0 {
		err := model.NewAppError("createPost", "api.post.create_post.can_not_post_to_deleted.error", nil, "", http.StatusBadRequest)
		return nil, err
	}

	rp, err := a.CreatePost(post, class, true)
	if err != nil {
		if err.Id == "api.post.create_post.root_id.app_error" ||
			err.Id == "api.post.create_post.class_root_id.app_error" ||
			err.Id == "api.post.create_post.parent_id.app_error" {
			err.StatusCode = http.StatusBadRequest
		}

		if err.Id == "api.post.create_post.town_square_read_only" {
			user, userErr := a.Srv().Store.User().Get(post.UserId)
			if userErr != nil {
				return nil, userErr
			}

			T := utils.GetUserTranslations(user.Locale)
			a.SendEphemeralPost(
				post.UserId,
				&model.Post{
					ClassId:  class.Id,
					UserId:   post.UserId,
					Message:  T("api.post.create_post.town_square_read_only"),
					CreateAt: model.GetMillis() + 1,
				},
			)
		}
		return nil, err
	}

	// Update the LastViewAt only if the post does not have from_webhook prop set (eg. Zapier app)
	// if _, ok := post.GetProps()["from_webhook"]; !ok {
	// 	if _, err := a.MarkClassesAsViewed([]string{post.ClassId}, post.UserId, currentSessionId); err != nil {
	// 		mlog.Error(
	// 			"Encountered error updating last viewed",
	// 			mlog.String("class_id", post.ClassId),
	// 			mlog.String("user_id", post.UserId),
	// 			mlog.Err(err),
	// 		)
	// 	}
	// }

	return rp, nil
}

func (a *App) CreatePostMissingClass(post *model.Post, triggerWebhooks bool) (*model.Post, *model.AppError) {
	class, err := a.Srv().Store.Class().Get(post.ClassId, true)
	if err != nil {
		return nil, err
	}

	return a.CreatePost(post, class, triggerWebhooks)
}

// deduplicateCreatePost attempts to make posting idempotent within a caching window.
func (a *App) deduplicateCreatePost(post *model.Post) (foundPost *model.Post, err *model.AppError) {
	// We rely on the client sending the pending post id across "duplicate" requests. If there
	// isn't one, we can't deduplicate, so allow creation normally.
	if post.PendingPostId == "" {
		return nil, nil
	}

	const unknownPostId = ""

	// Query the cache atomically for the given pending post id, saving a record if
	// it hasn't previously been seen.
	value, loaded := a.Srv().seenPendingPostIdsCache.GetOrAdd(post.PendingPostId, unknownPostId, PENDING_POST_IDS_CACHE_TTL)

	// If we were the first thread to save this pending post id into the cache,
	// proceed with create post normally.
	if !loaded {
		return nil, nil
	}

	postId := value.(string)

	// If another thread saved the cache record, but hasn't yet updated it with the actual post
	// id (because it's still saving), notify the client with an error. Ideally, we'd wait
	// for the other thread, but coordinating that adds complexity to the happy path.
	if postId == unknownPostId {
		return nil, model.NewAppError("deduplicateCreatePost", "api.post.deduplicate_create_post.pending", nil, "", http.StatusInternalServerError)
	}

	// If the other thread finished creating the post, return the created post back to the
	// client, making the API call feel idempotent.
	actualPost, err := a.GetSinglePost(postId)
	if err != nil {
		return nil, model.NewAppError("deduplicateCreatePost", "api.post.deduplicate_create_post.failed_to_get", nil, err.Error(), http.StatusInternalServerError)
	}

	mlog.Debug("Deduplicated create post", mlog.String("post_id", actualPost.Id), mlog.String("pending_post_id", post.PendingPostId))

	return actualPost, nil
}

func (a *App) CreatePost(post *model.Post, class *model.Class, triggerWebhooks bool) (savedPost *model.Post, err *model.AppError) {
	foundPost, err := a.deduplicateCreatePost(post)
	if err != nil {
		return nil, err
	}
	if foundPost != nil {
		return foundPost, nil
	}

	// If we get this far, we've recorded the client-provided pending post id to the cache.
	// Remove it if we fail below, allowing a proper retry by the client.
	defer func() {
		if post.PendingPostId == "" {
			return
		}

		if err != nil {
			a.Srv().seenPendingPostIdsCache.Remove(post.PendingPostId)
			return
		}

		a.Srv().seenPendingPostIdsCache.AddWithExpiresInSecs(post.PendingPostId, savedPost.Id, int64(PENDING_POST_IDS_CACHE_TTL.Seconds()))
	}()

	post.SanitizeProps()

	// var pchan chan store.StoreResult
	// if len(post.RootId) > 0 {
	// 	pchan = make(chan store.StoreResult, 1)
	// 	go func() {
	// 		r, pErr := a.Srv().Store.Post().Get(post.RootId, false)
	// 		pchan <- store.StoreResult{Data: r, Err: pErr}
	// 		close(pchan)
	// 	}()
	// }

	user, err := a.Srv().Store.User().Get(post.UserId)
	if err != nil {
		return nil, err
	}

	if user.IsBot {
		post.AddProp("from_bot", "true")
	}

	if a.License() != nil && *a.Config().BranchSettings.ExperimentalTownSquareIsReadOnly &&
		!post.IsSystemMessage() &&
		!a.RolesGrantPermission(user.GetRoles(), model.PERMISSION_MANAGE_SYSTEM.Id) {
		return nil, model.NewAppError("createPost", "api.post.create_post.town_square_read_only", nil, "", http.StatusForbidden)
	}

	var ephemeralPost *model.Post
	if post.Type == "" && !a.HasPermissionToClass(user.Id, class.Id, model.PERMISSION_USE_CLASS_MENTIONS) {
		mention := post.DisableMentionHighlights()
		if mention != "" {
			T := utils.GetUserTranslations(user.Locale)
			ephemeralPost = &model.Post{
				UserId:  user.Id,
				ClassId: class.Id,
				Message: T("model.post.class_notifications_disabled_in_class.message", model.StringInterface{"ClassName": class.Name, "Mention": mention}),
				Props:   model.StringInterface{model.POST_PROPS_MENTION_HIGHLIGHT_DISABLED: true},
			}
		}
	}

	post.Hashtags, _ = model.ParseHashtags(post.Message)

	// if err = a.FillInPostProps(post, class); err != nil {
	// 	return nil, err
	// }

	// Temporary fix so old plugins don't clobber new fields in SlackAttachment struct, see MM-13088
	if attachments, ok := post.GetProp("attachments").([]*model.SlackAttachment); ok {
		jsonAttachments, err := json.Marshal(attachments)
		if err == nil {
			attachmentsInterface := []interface{}{}
			err = json.Unmarshal(jsonAttachments, &attachmentsInterface)
			post.AddProp("attachments", attachmentsInterface)
		}
		if err != nil {
			mlog.Error("Could not convert post attachments to map interface.", mlog.Err(err))
		}
	}

	rpost, err := a.Srv().Store.Post().Save(post)
	if err != nil {
		return nil, err
	}

	// Update the mapping from pending post id to the actual post id, for any clients that
	// might be duplicating requests.
	a.Srv().seenPendingPostIdsCache.AddWithExpiresInSecs(post.PendingPostId, rpost.Id, int64(PENDING_POST_IDS_CACHE_TTL.Seconds()))

	if a.Metrics() != nil {
		a.Metrics().IncrementPostCreate()
	}

	if len(post.FileIds) > 0 {
		if err = a.attachFilesToPost(post); err != nil {
			mlog.Error("Encountered error attaching files to post", mlog.String("post_id", post.Id), mlog.Any("file_ids", post.FileIds), mlog.Err(err))
		}

		if a.Metrics() != nil {
			a.Metrics().IncrementPostFileAttachment(len(post.FileIds))
		}
	}

	// Normally, we would let the API layer call PreparePostForClient, but we do it here since it also needs
	// to be done when we send the post over the websocket in handlePostEvents
	rpost = a.PreparePostForClient(rpost, true, false)

	// if err := a.handlePostEvents(rpost, user, class, triggerWebhooks, parentPostList); err != nil {
	// 	mlog.Error("Failed to handle post events", mlog.Err(err))
	// }

	// Send any ephemeral posts after the post is created to ensure it shows up after the latest post created
	if ephemeralPost != nil {
		a.SendEphemeralPost(post.UserId, ephemeralPost)
	}

	return rpost, nil
}

func (a *App) attachFilesToPost(post *model.Post) *model.AppError {
	var attachedIds []string
	for _, fileId := range post.FileIds {
		err := a.Srv().Store.FileInfo().AttachToPost(fileId, post.Id, post.UserId)
		if err != nil {
			mlog.Warn("Failed to attach file to post", mlog.String("file_id", fileId), mlog.String("post_id", post.Id), mlog.Err(err))
			continue
		}

		attachedIds = append(attachedIds, fileId)
	}

	if len(post.FileIds) != len(attachedIds) {
		// We couldn't attach all files to the post, so ensure that post.FileIds reflects what was actually attached
		post.FileIds = attachedIds

		if _, err := a.Srv().Store.Post().Overwrite(post); err != nil {
			return err
		}
	}

	return nil
}

// FillInPostProps should be invoked before saving posts to fill in properties such as
// class_mentions.
//
// If class is nil, FillInPostProps will look up the class corresponding to the post.
/*func (a *App) FillInPostProps(post *model.Post, class *model.Class) *model.AppError {
	classMentions := post.ClassMentions()
	classMentionsProp := make(map[string]interface{})

	if len(classMentions) > 0 {
		if class == nil {
			postClass, err := a.Srv().Store.Class().GetForPost(post.Id)
			if err != nil {
				return model.NewAppError("FillInPostProps", "api.context.invalid_param.app_error", map[string]interface{}{"Name": "post.class_id"}, err.Error(), http.StatusBadRequest)
			}
			class = postClass
		}

		mentionedClasses, err := a.GetClassesByNames(classMentions, class.BranchId)
		if err != nil {
			return err
		}

		for _, mentioned := range mentionedClasses {
			if mentioned.Type == model.CLASS_OPEN {
				branch, err := a.Srv().Store.Branch().Get(mentioned.BranchId)
				if err != nil {
					mlog.Error("Failed to get branch of the class mention", mlog.String("branch_id", class.BranchId), mlog.String("class_id", class.Id), mlog.Err(err))
				}
				classMentionsProp[mentioned.Name] = map[string]interface{}{
					"display_name": mentioned.DisplayName,
					"branch_name":  branch.Name,
				}
			}
		}
	}

	if len(classMentionsProp) > 0 {
		post.AddProp("class_mentions", classMentionsProp)
	} else if post.GetProps() != nil {
		post.DelProp("class_mentions")
	}

	return nil
}

func (a *App) handlePostEvents(post *model.Post, user *model.User, class *model.Class, triggerWebhooks bool, parentPostList *model.PostList) error {
	var branch *model.Branch
	if len(class.BranchId) > 0 {
		t, err := a.Srv().Store.Branch().Get(class.BranchId)
		if err != nil {
			return err
		}
		branch = t
	} else {
		// Blank branch for DMs
		branch = &model.Branch{}
	}

	a.invalidateCacheForClass(class)
	a.invalidateCacheForClassPosts(class.Id)

	if _, err := a.SendNotifications(post, branch, class, user, parentPostList); err != nil {
		return err
	}

	a.Srv().Go(func() {
		_, err := a.SendAutoResponseIfNecessary(class, user)
		if err != nil {
			mlog.Error("Failed to send auto response", mlog.String("user_id", user.Id), mlog.String("post_id", post.Id), mlog.Err(err))
		}
	})

	if triggerWebhooks {
		a.Srv().Go(func() {
			if err := a.handleWebhookEvents(post, branch, class, user); err != nil {
				mlog.Error(err.Error())
			}
		})
	}

	return nil
}
*/
func (a *App) SendEphemeralPost(userId string, post *model.Post) *model.Post {
	post.Type = model.POST_EPHEMERAL

	// fill in fields which haven't been specified which have sensible defaults
	if post.Id == "" {
		post.Id = model.NewId()
	}
	if post.CreateAt == 0 {
		post.CreateAt = model.GetMillis()
	}
	if post.GetProps() == nil {
		post.SetProps(make(model.StringInterface))
	}

	post.GenerateActionIds()
	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_EPHEMERAL_MESSAGE, "", post.ClassId, userId, nil)
	post = a.PreparePostForClient(post, true, false)
	post = model.AddPostActionCookies(post, a.PostActionCookieSecret())
	message.Add("post", post.ToJson())
	a.Publish(message)

	return post
}

func (a *App) UpdateEphemeralPost(userId string, post *model.Post) *model.Post {
	post.Type = model.POST_EPHEMERAL

	post.UpdateAt = model.GetMillis()
	if post.GetProps() == nil {
		post.SetProps(make(model.StringInterface))
	}

	post.GenerateActionIds()
	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_POST_EDITED, "", post.ClassId, userId, nil)
	post = a.PreparePostForClient(post, true, false)
	post = model.AddPostActionCookies(post, a.PostActionCookieSecret())
	message.Add("post", post.ToJson())
	a.Publish(message)

	return post
}

func (a *App) DeleteEphemeralPost(userId, postId string) {
	post := &model.Post{
		Id:       postId,
		UserId:   userId,
		Type:     model.POST_EPHEMERAL,
		DeleteAt: model.GetMillis(),
		UpdateAt: model.GetMillis(),
	}

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_POST_DELETED, "", "", userId, nil)
	message.Add("post", post.ToJson())
	a.Publish(message)
}

func (a *App) UpdatePost(post *model.Post, safeUpdate bool) (*model.Post, *model.AppError) {
	post.SanitizeProps()

	postLists, err := a.Srv().Store.Post().Get(post.Id, false)
	if err != nil {
		return nil, err
	}
	oldPost := postLists.Posts[post.Id]

	if oldPost == nil {
		err = model.NewAppError("UpdatePost", "api.post.update_post.find.app_error", nil, "id="+post.Id, http.StatusBadRequest)
		return nil, err
	}

	if oldPost.DeleteAt != 0 {
		err = model.NewAppError("UpdatePost", "api.post.update_post.permissions_details.app_error", map[string]interface{}{"PostId": post.Id}, "", http.StatusBadRequest)
		return nil, err
	}

	if oldPost.IsSystemMessage() {
		err = model.NewAppError("UpdatePost", "api.post.update_post.system_message.app_error", nil, "id="+post.Id, http.StatusBadRequest)
		return nil, err
	}

	if a.License() != nil {
		if *a.Config().ServiceSettings.PostEditTimeLimit != -1 && model.GetMillis() > oldPost.CreateAt+int64(*a.Config().ServiceSettings.PostEditTimeLimit*1000) && post.Message != oldPost.Message {
			err = model.NewAppError("UpdatePost", "api.post.update_post.permissions_time_limit.app_error", map[string]interface{}{"timeLimit": *a.Config().ServiceSettings.PostEditTimeLimit}, "", http.StatusBadRequest)
			return nil, err
		}
	}

	class, err := a.GetClass(oldPost.ClassId)
	if err != nil {
		return nil, err
	}

	if class.DeleteAt != 0 {
		return nil, model.NewAppError("UpdatePost", "api.post.update_post.can_not_update_post_in_deleted.error", nil, "", http.StatusBadRequest)
	}

	newPost := &model.Post{}
	newPost = oldPost.Clone()

	if newPost.Message != post.Message {
		newPost.Message = post.Message
		newPost.EditAt = model.GetMillis()
		newPost.Hashtags, _ = model.ParseHashtags(post.Message)
	}

	if !safeUpdate {
		newPost.HasReactions = post.HasReactions
		newPost.FileIds = post.FileIds
		newPost.SetProps(post.GetProps())
	}

	// Avoid deep-equal checks if EditAt was already modified through message change
	if newPost.EditAt == oldPost.EditAt && (!oldPost.FileIds.Equals(newPost.FileIds) || !oldPost.AttachmentsEqual(newPost)) {
		newPost.EditAt = model.GetMillis()
	}

	// if err = a.FillInPostProps(post, nil); err != nil {
	// 	return nil, err
	// }

	rpost, err := a.Srv().Store.Post().Update(newPost, oldPost)
	if err != nil {
		return nil, err
	}

	rpost = a.PreparePostForClient(rpost, false, true)

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_POST_EDITED, "", rpost.ClassId, "", nil)
	message.Add("post", rpost.ToJson())
	a.Publish(message)

	// a.invalidateCacheForClassPosts(rpost.ClassId)

	return rpost, nil
}

func (a *App) PatchPost(postId string, patch *model.PostPatch) (*model.Post, *model.AppError) {
	post, err := a.GetSinglePost(postId)
	if err != nil {
		return nil, err
	}

	class, err := a.GetClass(post.ClassId)
	if err != nil {
		return nil, err
	}

	if class.DeleteAt != 0 {
		err = model.NewAppError("PatchPost", "api.post.patch_post.can_not_update_post_in_deleted.error", nil, "", http.StatusBadRequest)
		return nil, err
	}

	if !a.HasPermissionToClass(post.UserId, post.ClassId, model.PERMISSION_USE_CLASS_MENTIONS) {
		patch.DisableMentionHighlights()
	}

	post.Patch(patch)

	updatedPost, err := a.UpdatePost(post, false)
	if err != nil {
		return nil, err
	}

	return updatedPost, nil
}

func (a *App) GetPostsPage(options model.GetPostsOptions) (*model.PostList, *model.AppError) {
	return a.Srv().Store.Post().GetPosts(options, false)
}

func (a *App) GetPosts(classId string, offset int, limit int) (*model.PostList, *model.AppError) {
	return a.Srv().Store.Post().GetPosts(model.GetPostsOptions{ClassId: classId, Page: offset, PerPage: limit}, true)
}

func (a *App) GetPostsEtag(classId string) string {
	return a.Srv().Store.Post().GetEtag(classId, true)
}

func (a *App) GetPostsSince(options model.GetPostsSinceOptions) (*model.PostList, *model.AppError) {
	return a.Srv().Store.Post().GetPostsSince(options, true)
}

func (a *App) GetSinglePost(postId string) (*model.Post, *model.AppError) {
	return a.Srv().Store.Post().GetSingle(postId)
}

func (a *App) GetFlaggedPosts(userId string, offset int, limit int) (*model.PostList, *model.AppError) {
	return a.Srv().Store.Post().GetFlaggedPosts(userId, offset, limit)
}

func (a *App) GetFlaggedPostsForBranch(userId, branchId string, offset int, limit int) (*model.PostList, *model.AppError) {
	return a.Srv().Store.Post().GetFlaggedPostsForBranch(userId, branchId, offset, limit)
}

func (a *App) GetFlaggedPostsForClass(userId, classId string, offset int, limit int) (*model.PostList, *model.AppError) {
	return a.Srv().Store.Post().GetFlaggedPostsForClass(userId, classId, offset, limit)
}

func (a *App) GetPermalinkPost(postId string, userId string) (*model.PostList, *model.AppError) {
	list, err := a.Srv().Store.Post().Get(postId, false)
	if err != nil {
		return nil, err
	}

	if len(list.Order) != 1 {
		return nil, model.NewAppError("getPermalinkTmp", "api.post_get_post_by_id.get.app_error", nil, "", http.StatusNotFound)
	}
	post := list.Posts[list.Order[0]]

	class, err := a.GetClass(post.ClassId)
	if err != nil {
		return nil, err
	}

	if err = a.JoinClass(class, userId); err != nil {
		return nil, err
	}

	return list, nil
}

func (a *App) GetPostsBeforePost(options model.GetPostsOptions) (*model.PostList, *model.AppError) {
	return a.Srv().Store.Post().GetPostsBefore(options)
}

func (a *App) GetPostsAfterPost(options model.GetPostsOptions) (*model.PostList, *model.AppError) {
	return a.Srv().Store.Post().GetPostsAfter(options)
}

func (a *App) GetPostsAroundPost(before bool, options model.GetPostsOptions) (*model.PostList, *model.AppError) {
	if before {
		return a.Srv().Store.Post().GetPostsBefore(options)
	}
	return a.Srv().Store.Post().GetPostsAfter(options)
}

func (a *App) GetPostAfterTime(classId string, time int64) (*model.Post, *model.AppError) {
	return a.Srv().Store.Post().GetPostAfterTime(classId, time)
}

func (a *App) GetPostIdAfterTime(classId string, time int64) (string, *model.AppError) {
	return a.Srv().Store.Post().GetPostIdAfterTime(classId, time)
}

func (a *App) GetPostIdBeforeTime(classId string, time int64) (string, *model.AppError) {
	return a.Srv().Store.Post().GetPostIdBeforeTime(classId, time)
}

func (a *App) GetNextPostIdFromPostList(postList *model.PostList) string {
	if len(postList.Order) > 0 {
		firstPostId := postList.Order[0]
		firstPost := postList.Posts[firstPostId]
		nextPostId, err := a.GetPostIdAfterTime(firstPost.ClassId, firstPost.CreateAt)
		if err != nil {
			mlog.Warn("GetNextPostIdFromPostList: failed in getting next post", mlog.Err(err))
		}

		return nextPostId
	}

	return ""
}

func (a *App) GetPrevPostIdFromPostList(postList *model.PostList) string {
	if len(postList.Order) > 0 {
		lastPostId := postList.Order[len(postList.Order)-1]
		lastPost := postList.Posts[lastPostId]
		previousPostId, err := a.GetPostIdBeforeTime(lastPost.ClassId, lastPost.CreateAt)
		if err != nil {
			mlog.Warn("GetPrevPostIdFromPostList: failed in getting previous post", mlog.Err(err))
		}

		return previousPostId
	}

	return ""
}

// AddCursorIdsForPostList adds NextPostId and PrevPostId as cursor to the PostList.
// The conditional blocks ensure that it sets those cursor IDs immediately as afterPost, beforePost or empty,
// and only query to database whenever necessary.
func (a *App) AddCursorIdsForPostList(originalList *model.PostList, afterPost, beforePost string, since int64, page, perPage int) {
	prevPostIdSet := false
	prevPostId := ""
	nextPostIdSet := false
	nextPostId := ""

	if since > 0 { // "since" query to return empty NextPostId and PrevPostId
		nextPostIdSet = true
		prevPostIdSet = true
	} else if afterPost != "" {
		if page == 0 {
			prevPostId = afterPost
			prevPostIdSet = true
		}

		if len(originalList.Order) < perPage {
			nextPostIdSet = true
		}
	} else if beforePost != "" {
		if page == 0 {
			nextPostId = beforePost
			nextPostIdSet = true
		}

		if len(originalList.Order) < perPage {
			prevPostIdSet = true
		}
	}

	if !nextPostIdSet {
		nextPostId = a.GetNextPostIdFromPostList(originalList)
	}

	if !prevPostIdSet {
		prevPostId = a.GetPrevPostIdFromPostList(originalList)
	}

	originalList.NextPostId = nextPostId
	originalList.PrevPostId = prevPostId
}

func (a *App) DeletePost(postId, deleteByID string) (*model.Post, *model.AppError) {
	post, err := a.Srv().Store.Post().GetSingle(postId)
	if err != nil {
		err.StatusCode = http.StatusBadRequest
		return nil, err
	}

	class, err := a.GetClass(post.ClassId)
	if err != nil {
		return nil, err
	}

	if class.DeleteAt != 0 {
		err := model.NewAppError("DeletePost", "api.post.delete_post.can_not_delete_post_in_deleted.error", nil, "", http.StatusBadRequest)
		return nil, err
	}

	if err := a.Srv().Store.Post().Delete(postId, model.GetMillis(), deleteByID); err != nil {
		return nil, err
	}

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_POST_DELETED, "", post.ClassId, "", nil)
	message.Add("post", a.PreparePostForClient(post, false, false).ToJson())
	a.Publish(message)

	a.Srv().Go(func() {
		a.DeletePostFiles(post)
	})
	a.Srv().Go(func() {
		a.DeleteFlaggedPosts(post.Id)
	})

	// a.invalidateCacheForClassPosts(post.ClassId)

	return post, nil
}

func (a *App) DeleteFlaggedPosts(postId string) {
	if err := a.Srv().Store.Preference().DeleteCategoryAndName(model.PREFERENCE_CATEGORY_FLAGGED_POST, postId); err != nil {
		mlog.Warn("Unable to delete flagged post preference when deleting post.", mlog.Err(err))
		return
	}
}

func (a *App) DeletePostFiles(post *model.Post) {
	if len(post.FileIds) == 0 {
		return
	}

	if _, err := a.Srv().Store.FileInfo().DeleteForPost(post.Id); err != nil {
		mlog.Warn("Encountered error when deleting files for post", mlog.String("post_id", post.Id), mlog.Err(err))
	}
}

func (a *App) convertUserNameToUserIds(usernames []string) []string {
	for idx, username := range usernames {
		if user, err := a.GetUserByUsername(username); err != nil {
			mlog.Error("error getting user by username", mlog.String("user_name", username), mlog.Err(err))
		} else {
			usernames[idx] = user.Id
		}
	}
	return usernames
}

func (a *App) GetFileInfosForPostWithMigration(postId string) ([]*model.FileInfo, *model.AppError) {

	pchan := make(chan store.StoreResult, 1)
	go func() {
		post, err := a.Srv().Store.Post().GetSingle(postId)
		pchan <- store.StoreResult{Data: post, Err: err}
		close(pchan)
	}()

	infos, err := a.GetFileInfosForPost(postId, false)
	if err != nil {
		return nil, err
	}

	if len(infos) == 0 {
		// No FileInfos were returned so check if they need to be created for this post
		result := <-pchan
		if result.Err != nil {
			return nil, result.Err
		}
		post := result.Data.(*model.Post)

		if len(post.Filenames) > 0 {
			a.Srv().Store.FileInfo().InvalidateFileInfosForPostCache(postId, false)
			a.Srv().Store.FileInfo().InvalidateFileInfosForPostCache(postId, true)
			// The post has Filenames that need to be replaced with FileInfos
			infos = a.MigrateFilenamesToFileInfos(post)
		}
	}

	return infos, nil
}

func (a *App) GetFileInfosForPost(postId string, fromMaster bool) ([]*model.FileInfo, *model.AppError) {
	return a.Srv().Store.FileInfo().GetForPost(postId, fromMaster, false, true)
}

func (a *App) PostWithProxyAddedToImageURLs(post *model.Post) *model.Post {
	if f := a.ImageProxyAdder(); f != nil {
		return post.WithRewrittenImageURLs(f)
	}
	return post
}

func (a *App) PostWithProxyRemovedFromImageURLs(post *model.Post) *model.Post {
	if f := a.ImageProxyRemover(); f != nil {
		return post.WithRewrittenImageURLs(f)
	}
	return post
}

func (a *App) PostPatchWithProxyRemovedFromImageURLs(patch *model.PostPatch) *model.PostPatch {
	if f := a.ImageProxyRemover(); f != nil {
		return patch.WithRewrittenImageURLs(f)
	}
	return patch
}

func (a *App) ImageProxyAdder() func(string) string {
	if !*a.Config().ImageProxySettings.Enable {
		return nil
	}

	return func(url string) string {
		return a.Srv().ImageProxy.GetProxiedImageURL(url)
	}
}

func (a *App) ImageProxyRemover() (f func(string) string) {
	if !*a.Config().ImageProxySettings.Enable {
		return nil
	}

	return func(url string) string {
		return a.Srv().ImageProxy.GetUnproxiedImageURL(url)
	}
}

func (a *App) MaxPostSize() int {
	maxPostSize := a.Srv().Store.Post().GetMaxPostSize()
	if maxPostSize == 0 {
		return model.POST_MESSAGE_MAX_RUNES_V1
	}

	return maxPostSize
}
