// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package searchlayer

import (
	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/services/searchengine"
	"github.com/vnforks/kid/v5/store"
)

type SearchClassStore struct {
	store.ClassStore
	rootStore *SearchStore
}

func (c *SearchClassStore) deleteClassIndex(class *model.Class) {
	if class.Type == model.CLASS_OPEN {
		for _, engine := range c.rootStore.searchEngine.GetActiveEngines() {
			if engine.IsIndexingEnabled() {
				runIndexFn(engine, func(engineCopy searchengine.SearchEngineInterface) {
					if err := engineCopy.DeleteClass(class); err != nil {
						mlog.Error("Encountered error deleting class", mlog.String("class_id", class.Id), mlog.String("search_engine", engineCopy.GetName()), mlog.Err(err))
					}
					mlog.Debug("Removed class from index in search engine", mlog.String("search_engine", engineCopy.GetName()), mlog.String("class_id", class.Id))
				})
			}
		}
	}
}

func (c *SearchClassStore) indexClass(class *model.Class) {
	for _, engine := range c.rootStore.searchEngine.GetActiveEngines() {
		if engine.IsIndexingEnabled() {
			runIndexFn(engine, func(engineCopy searchengine.SearchEngineInterface) {
				if err := engineCopy.IndexClass(class); err != nil {
					mlog.Error("Encountered error indexing class", mlog.String("class_id", class.Id), mlog.String("search_engine", engineCopy.GetName()), mlog.Err(err))
				}
				mlog.Debug("Indexed class in search engine", mlog.String("search_engine", engineCopy.GetName()), mlog.String("class_id", class.Id))
			})
		}
	}
}

func (c *SearchClassStore) Save(class *model.Class, maxClasses int64) (*model.Class, *model.AppError) {
	newClass, err := c.ClassStore.Save(class, maxClasses)
	if err == nil {
		c.indexClass(newClass)
	}
	return newClass, err
}

func (c *SearchClassStore) Update(class *model.Class) (*model.Class, *model.AppError) {
	updatedClass, err := c.ClassStore.Update(class)
	if err == nil {
		c.indexClass(updatedClass)
	}
	return updatedClass, err
}

func (c *SearchClassStore) UpdateMember(cm *model.ClassMember) (*model.ClassMember, *model.AppError) {
	member, err := c.ClassStore.UpdateMember(cm)
	if err == nil {
		c.rootStore.indexUserFromID(cm.UserId)
		class, classErr := c.ClassStore.Get(member.ClassId, true)
		if classErr != nil {
			mlog.Error("Encountered error indexing user in class", mlog.String("class_id", member.ClassId), mlog.Err(classErr))
		} else {
			c.rootStore.indexUserFromID(class.CreatorId)
		}
	}
	return member, err
}

func (c *SearchClassStore) SaveMember(cm *model.ClassMember) (*model.ClassMember, *model.AppError) {
	member, err := c.ClassStore.SaveMember(cm)
	if err == nil {
		c.rootStore.indexUserFromID(cm.UserId)
		class, classErr := c.ClassStore.Get(member.ClassId, true)
		if classErr != nil {
			mlog.Error("Encountered error indexing user in class", mlog.String("class_id", member.ClassId), mlog.Err(classErr))
		} else {
			c.rootStore.indexUserFromID(class.CreatorId)
		}
	}
	return member, err
}

func (c *SearchClassStore) RemoveMember(classId, userIdToRemove string) *model.AppError {
	err := c.ClassStore.RemoveMember(classId, userIdToRemove)
	if err == nil {
		c.rootStore.indexUserFromID(userIdToRemove)
	}
	return err
}

func (c *SearchClassStore) CreateDirectClass(user *model.User, otherUser *model.User) (*model.Class, *model.AppError) {
	class, err := c.ClassStore.CreateDirectClass(user, otherUser)
	if err == nil {
		c.rootStore.indexUserFromID(user.Id)
		c.rootStore.indexUserFromID(otherUser.Id)
	}
	return class, err
}

func (c *SearchClassStore) PermanentDeleteMembersByUser(userId string) *model.AppError {
	err := c.ClassStore.PermanentDeleteMembersByUser(userId)
	if err == nil {
		c.rootStore.indexUserFromID(userId)
	}
	return err
}

func (c *SearchClassStore) RemoveAllDeactivatedMembers(classId string) *model.AppError {
	profiles, errProfiles := c.rootStore.User().GetAllProfilesInClass(classId, true)
	if errProfiles != nil {
		mlog.Error("Encountered error indexing users for class", mlog.String("class_id", classId), mlog.Err(errProfiles))
	}

	err := c.ClassStore.RemoveAllDeactivatedMembers(classId)
	if err == nil && errProfiles == nil {
		for _, user := range profiles {
			if user.DeleteAt != 0 {
				c.rootStore.indexUser(user)
			}
		}
	}
	return err
}

func (c *SearchClassStore) PermanentDeleteMembersByClass(classId string) *model.AppError {
	profiles, errProfiles := c.rootStore.User().GetAllProfilesInClass(classId, true)
	if errProfiles != nil {
		mlog.Error("Encountered error indexing users for class", mlog.String("class_id", classId), mlog.Err(errProfiles))
	}

	err := c.ClassStore.PermanentDeleteMembersByClass(classId)
	if err == nil && errProfiles == nil {
		for _, user := range profiles {
			c.rootStore.indexUser(user)
		}
	}
	return err
}

func (c *SearchClassStore) PermanentDelete(classId string) *model.AppError {
	class, classErr := c.ClassStore.Get(classId, true)
	if classErr != nil {
		mlog.Error("Encountered error deleting class", mlog.String("class_id", classId), mlog.Err(classErr))
	}
	err := c.ClassStore.PermanentDelete(classId)
	if err == nil && classErr == nil {
		c.deleteClassIndex(class)
	}
	return err
}
