package gocaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/pristine/gocaptcha/internal"
)

type EzCaptcha struct {
	apiKey  string
	baseUrl string
}

func NewEzCaptcha(apiKey string) *EzCaptcha {
	return &EzCaptcha{apiKey: apiKey, baseUrl: "https://api.ez-captcha.com"}
}

func (t *EzCaptcha) SolveImageCaptcha(ctx context.Context, settings *Settings, payload *ImageCaptchaPayload) (ICaptchaResponse, error) {
	panic("not implemented")
}

func (t *EzCaptcha) SolveRecaptchaV2(ctx context.Context, settings *Settings, payload *RecaptchaV2Payload) (ICaptchaResponse, error) {
	panic("not implemented")
}

func (t *EzCaptcha) SolveRecaptchaV3(ctx context.Context, settings *Settings, payload *RecaptchaV3Payload) (ICaptchaResponse, error) {
	panic("not implemented")
}

func (t *EzCaptcha) SolveHCaptcha(ctx context.Context, settings *Settings, payload *HCaptchaPayload) (ICaptchaResponse, error) {
	panic("not implemented")
}

func (t *EzCaptcha) SolveTurnstile(ctx context.Context, settings *Settings, payload *TurnstilePayload) (ICaptchaResponse, error) {
	panic("not implemented")
}

func (t *EzCaptcha) SolveFunCaptcha(ctx context.Context, settings *Settings, payload *FunCaptchaPayload) (ICaptchaResponse, error) {
	task := map[string]interface{}{}
	task["type"] = "FuncaptchaTaskProxyless"
	task["websiteKey"] = payload.EndpointKey
	task["websiteURL"] = payload.EndpointUrl

	result, err := t.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *EzCaptcha) report(action, taskId string, settings *Settings) func(ctx context.Context) error {
	panic("not implemented")
}

func (t *EzCaptcha) solveTask(ctx context.Context, settings *Settings, task map[string]interface{}) (*CaptchaResponse, error) {
	taskId, err := t.createTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	if err := internal.SleepWithContext(ctx, settings.initialWaitTime); err != nil {
		return nil, err
	}

	for i := 0; i < settings.maxRetries; i++ {
		answer, err := t.getResult(ctx, settings, taskId)
		if err != nil {
			return nil, err
		}

		if answer != "" {
			return &CaptchaResponse{solution: answer, taskId: taskId}, nil
		}

		if err := internal.SleepWithContext(ctx, settings.pollInterval); err != nil {
			return nil, err
		}
	}

	return nil, errors.New("max tries exceeded")
}

func (t *EzCaptcha) createTask(ctx context.Context, settings *Settings, payload map[string]interface{}) (string, error) {
	type response struct {
		TaskId           string `json:"taskId"`
		ErrorId          int    `json:"errorId"`
		ErrorCode        string `json:"errorCode"`
		ErrorDescription string `json:"errorDescription"`
	}

	body := map[string]interface{}{
		"clientKey": t.apiKey,
		"task":      payload,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%v/createTask", t.baseUrl), bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", nil
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := settings.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var jsonResp response
	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		return "", err
	}

	if jsonResp.ErrorId == 1 {
		return "", fmt.Errorf("%v: %v", jsonResp.ErrorCode, jsonResp.ErrorDescription)
	}

	return jsonResp.TaskId, nil
}

func (t *EzCaptcha) getResult(ctx context.Context, settings *Settings, taskId string) (string, error) {
	type response struct {
		ErrorId          int         `json:"errorId"`
		ErrorCode        string      `json:"errorCode"`
		ErrorDescription string      `json:"errorDescription"`
		Solution         interface{} `json:"solution"`
		Status           string      `json:"status"`
	}

	body := map[string]interface{}{
		"clientKey": t.apiKey,
		"taskId":    taskId,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%v/getTaskResult", t.baseUrl), bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := settings.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var jsonResp response
	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		return "", err
	}

	if jsonResp.ErrorId == 1 {
		return "", fmt.Errorf("%v: %v", jsonResp.ErrorCode, jsonResp.ErrorDescription)
	}

	if jsonResp.Status != "ready" {
		return "", nil
	}

	solutionBytes, err := json.Marshal(jsonResp.Solution)
	if err != nil {
		return "", err
	}

	return string(solutionBytes), nil
}

var _ IProvider = (*EzCaptcha)(nil)
