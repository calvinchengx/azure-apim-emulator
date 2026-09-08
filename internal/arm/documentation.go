package arm

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

var documentationName = regexp.MustCompile(`^[^*#&+:<>?]+$`)

type documentationPayload struct {
	Properties struct {
		Title   *string `json:"title"`
		Content *string `json:"content"`
	} `json:"properties"`
}

func (h *Handler) documentation(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListDocumentations(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, documentationWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested documentation resource was not found.", r.URL.Path)
		return
	}
	if rt.Tail[1] == "" || len(rt.Tail[1]) > 256 || !documentationName.MatchString(rt.Tail[1]) {
		writeError(w, http.StatusBadRequest, "ValidationError", "documentationId must be 1-256 characters and must not contain * # & + : < > ?", "documentationId")
		return
	}
	value := model.Documentation{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetDocumentation(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, documentationWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetDocumentation(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value.Name = existing.Name
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body documentationPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = documentationWire(value)
			}
			mergeObject(value.Document, document)
			clearNullDocumentationProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		applyDocumentationPayload(&value, body)
		if err := validateDocumentation(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertDocumentation(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, documentationWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteDocumentation(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyDocumentationPayload(value *model.Documentation, body documentationPayload) {
	if body.Properties.Title != nil {
		value.Title = *body.Properties.Title
	}
	if body.Properties.Content != nil {
		value.Content = *body.Properties.Content
	}
}

func clearNullDocumentationProperties(value *model.Documentation, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["content"]; present && field == nil {
		value.Content = ""
	}
}

func validateDocumentation(value model.Documentation, creating bool) error {
	if creating && value.Title == "" {
		return errors.New("title is required")
	}
	if value.Title == "" {
		return errors.New("title cannot be empty")
	}
	return nil
}

func documentationWire(v model.Documentation) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/documentations"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["title"] = v.Title
	properties["content"] = v.Content
	return result
}
