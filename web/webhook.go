// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package web

import (
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"

	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
)

func (w *Web) InitWebhooks() {
	w.MainRouter.Handle("/hooks/commands/{id:[A-Za-z0-9]+}", w.NewHandler(commandWebhook)).Methods("POST")
	w.MainRouter.Handle("/hooks/{id:[A-Za-z0-9]+}", w.NewHandler(incomingWebhook)).Methods("POST")
}

func incomingWebhook(c *Context, w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	r.ParseForm()

	var err *model.AppError
	incomingWebhookPayload := &model.IncomingWebhookRequest{}
	mediaType, _, mimeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mimeErr != nil && mimeErr != mime.ErrInvalidMediaParameter {
		c.Err = model.NewAppError("incomingWebhook", "api.webhook.incoming.error", nil, mimeErr.Error(), http.StatusBadRequest)
		return
	}

	defer func() {
		if *c.App.Config().LogSettings.EnableWebhookDebugging {
			if c.Err != nil {
				mlog.Debug("Incoming webhook received", mlog.String("webhook_id", id), mlog.String("request_id", c.App.RequestId()), mlog.String("payload", incomingWebhookPayload.ToJson()))
			}
		}
	}()

	if mediaType == "application/x-www-form-urlencoded" {
		payload := strings.NewReader(r.FormValue("payload"))

		incomingWebhookPayload, err = decodePayload(payload)
		if err != nil {
			c.Err = err
			return
		}
	} else if mediaType == "multipart/form-data" {
		r.ParseMultipartForm(0)

		decoder := schema.NewDecoder()
		err := decoder.Decode(incomingWebhookPayload, r.PostForm)

		if err != nil {
			c.Err = model.NewAppError("incomingWebhook", "api.webhook.incoming.error", nil, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		incomingWebhookPayload, err = decodePayload(r.Body)
		if err != nil {
			c.Err = err
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}

func commandWebhook(c *Context, w http.ResponseWriter, r *http.Request) {

	_, err := model.CommandResponseFromHTTPBody(r.Header.Get("Content-Type"), r.Body)
	if err != nil {
		c.Err = model.NewAppError("commandWebhook", "web.command_webhook.parse.app_error", nil, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}

func decodePayload(payload io.Reader) (*model.IncomingWebhookRequest, *model.AppError) {
	incomingWebhookPayload, decodeError := model.IncomingWebhookRequestFromJson(payload)

	if decodeError != nil {
		return nil, decodeError
	}

	return incomingWebhookPayload, nil
}
