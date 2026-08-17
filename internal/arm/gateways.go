package arm

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// Self-hosted gateways.
//
// The resource registers a gateway that runs somewhere else. Azure issues it a
// key pair, mints tokens from that pair, and records which APIs it may serve;
// the gateway process itself collects that configuration and answers on its own
// hostnames. This file is the management half. The runtime half is the hostname
// routing in internal/gateway: a request arriving on a gateway's hostname is
// served by that gateway, and therefore only by the APIs associated with it.
//
// What is deliberately NOT here is the configuration-sync protocol the
// self-hosted gateway container speaks. Its payload format is proprietary and
// this emulator has never captured it, so inventing one would produce a surface
// that passes its own tests forever and that no real gateway has ever spoken
// to. `docs/parity.md` records that as pending rather than implied.

// tokenExpiryLayout is .NET's `yyyy-MM-ddTHH:mm:ss.fffffffZ`: seven fractional
// digits, always emitted. Go's `.9999999` would trim trailing zeros and produce
// a different string for the same instant, and the string is what gets signed.
const tokenExpiryLayout = "2006-01-02T15:04:05.0000000Z"

// maxTokenLifetime is Azure's documented ceiling on a gateway token.
const maxTokenLifetime = 30 * 24 * time.Hour

// gatewayRoute dispatches the self-hosted gateway resource tree.
func (h *Handler) gatewayRoute(w http.ResponseWriter, r *http.Request, rt route) {
	// The workspace scope is refused centrally, by serviceOnlyFamilies in
	// handler.go: a workspace gets a gateway through the separate top-level
	// Microsoft.ApiManagement/gateways resource, never through this path.
	serviceID := rt.service().ID()
	switch len(rt.Tail) {
	case 1:
		h.gatewayCollection(w, r, serviceID)
	case 2:
		h.gatewayResource(w, r, model.Gateway{ServiceID: serviceID, Name: rt.Tail[1]})
	default:
		h.gatewayChildRoute(w, r, rt, serviceID)
	}
}

// gatewayChildRoute serves everything addressed beneath one gateway: its API
// associations, hostnames, certificate authorities, and its POST actions.
func (h *Handler) gatewayChildRoute(w http.ResponseWriter, r *http.Request, rt route, serviceID string) {
	gatewayID := serviceID + "/gateways/" + rt.Tail[1]
	// The gateway must exist before anything beneath it is addressable,
	// otherwise a typo in the gateway name silently associates an API with a
	// gateway nobody registered.
	gateway, err := h.Store.GetGateway(gatewayID)
	if err != nil {
		h.storeError(w, err, gatewayID)
		return
	}
	switch {
	case equal(rt.Tail[2], "apis"):
		h.gatewayAPIRoute(w, r, rt, gateway)
	case equal(rt.Tail[2], "hostnameConfigurations"):
		h.gatewayHostnameRoute(w, r, rt, gateway)
	case equal(rt.Tail[2], "certificateAuthorities"):
		h.gatewayCertificateAuthorityRoute(w, r, rt, gateway)
	case len(rt.Tail) == 3:
		h.gatewayAction(w, r, gateway, rt.Tail[2])
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", gatewayID)
	}
}

func (h *Handler) gatewayCollection(w http.ResponseWriter, r *http.Request, serviceID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListGateways(serviceID)
	if err != nil {
		h.storeError(w, err, serviceID)
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, gatewayWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) gatewayResource(w http.ResponseWriter, r *http.Request, value model.Gateway) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetGateway(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, gatewayWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		h.gatewayUpsert(w, r, value)
	case http.MethodDelete:
		if err := h.Store.DeleteGateway(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		// Removing the registration removes the gateway's hostnames, so the
		// runtime snapshot has to be rebuilt or requests would keep resolving
		// to a gateway that no longer exists.
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) gatewayUpsert(w http.ResponseWriter, r *http.Request, value model.Gateway) {
	if store.GatewayNameReserved(value.Name) {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"The gateway identifier \"managed\" names the service's built-in gateway and cannot be registered.", "gatewayId")
		return
	}
	existing, existingErr := h.Store.GetGateway(value.ID())
	if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
		h.storeError(w, existingErr, value.ID())
		return
	}
	// The service must exist. The foreign key would reject it anyway, but as a
	// 409 rather than the 404 a missing parent deserves.
	if _, err := h.Store.GetService(value.ServiceID); err != nil {
		h.storeError(w, err, value.ServiceID)
		return
	}
	if r.Method == http.MethodPatch {
		if existingErr != nil {
			h.storeError(w, existingErr, value.ID())
			return
		}
		value = existing
	} else if existingErr == nil {
		// A PUT replaces the resource's properties, but the keys are not
		// properties: they are never sent by the caller and never returned by a
		// GET, so taking them from the request body would blank them on every
		// update and silently invalidate every token already minted.
		value.PrimaryKey, value.SecondaryKey = existing.PrimaryKey, existing.SecondaryKey
	}
	var body struct {
		Properties struct {
			LocationData *struct {
				Name *string `json:"name"`
			} `json:"locationData"`
			Description *string `json:"description"`
		} `json:"properties"`
	}
	var document map[string]any
	if err := decodeDocument(r, &body, &document); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
		return
	}
	if body.Properties.LocationData != nil && body.Properties.LocationData.Name != nil {
		value.LocationName = *body.Properties.LocationData.Name
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if strings.TrimSpace(value.LocationName) == "" {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"properties.locationData.name is required: a gateway records where it runs.", "properties.locationData.name")
		return
	}
	if errors.Is(existingErr, store.ErrNotFound) {
		// Keys are issued once, at registration. An update must not reissue
		// them: that would revoke every token already minted from the old pair,
		// which is a change nobody asked for.
		value.PrimaryKey, value.SecondaryKey = store.NewOpaqueID(), store.NewOpaqueID()
	}
	value.Document = document
	cleanResourceDocument(value.Document)
	got, err := h.Store.UpsertGateway(value)
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	status := http.StatusOK
	if errors.Is(existingErr, store.ErrNotFound) {
		status = http.StatusCreated
	}
	writeResource(w, status, gatewayWire(got), got.ETag)
}

// gatewayAction serves the POST operations on a gateway: its keys, and the
// tokens minted from them.
func (h *Handler) gatewayAction(w http.ResponseWriter, r *http.Request, gateway model.Gateway, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	switch strings.ToLower(action) {
	case "listkeys":
		writeJSON(w, http.StatusOK, map[string]any{"primary": gateway.PrimaryKey, "secondary": gateway.SecondaryKey})
	case "regeneratekey":
		h.gatewayRegenerateKey(w, r, gateway)
	case "generatetoken":
		h.gatewayGenerateToken(w, r, gateway)
	case "listdebugcredentials", "invalidatedebugcredentials", "listtrace":
		// These exist in Azure and are not implemented here. Answering 404
		// would say the operation does not exist, which is a different and
		// wrong claim; this fails loudly and names the gap.
		writeError(w, http.StatusNotImplemented, "NotImplemented",
			"Gateway debug credentials and trace retrieval are not implemented in this emulator.", gateway.ID())
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", gateway.ID())
	}
}

func (h *Handler) gatewayRegenerateKey(w http.ResponseWriter, r *http.Request, gateway model.Gateway) {
	var body struct {
		KeyType string `json:"keyType"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
		return
	}
	switch {
	case equal(body.KeyType, "primary"):
		gateway.PrimaryKey = store.NewOpaqueID()
	case equal(body.KeyType, "secondary"):
		gateway.SecondaryKey = store.NewOpaqueID()
	default:
		writeError(w, http.StatusBadRequest, "ValidationError", "keyType must be \"primary\" or \"secondary\".", "keyType")
		return
	}
	if _, err := h.Store.UpsertGateway(gateway); err != nil {
		h.storeError(w, err, gateway.ID())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) gatewayGenerateToken(w http.ResponseWriter, r *http.Request, gateway model.Gateway) {
	var body struct {
		KeyType string `json:"keyType"`
		Expiry  string `json:"expiry"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
		return
	}
	key := gateway.PrimaryKey
	switch {
	case equal(body.KeyType, "primary"):
	case equal(body.KeyType, "secondary"):
		key = gateway.SecondaryKey
	default:
		writeError(w, http.StatusBadRequest, "ValidationError", "keyType must be \"primary\" or \"secondary\".", "keyType")
		return
	}
	expiry, err := time.Parse(time.RFC3339, body.Expiry)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"properties.expiry must be an ISO 8601 instant, for example 2026-01-01T00:00:00Z.", "expiry")
		return
	}
	if expiry.Sub(time.Now().UTC()) > maxTokenLifetime {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"The maximum gateway token expiry is 30 days.", "expiry")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": gatewayToken(gateway.Name, expiry, key)})
}

// gatewayToken mints the token a self-hosted gateway presents for its
// configuration: `{id}&{expiry}&{signature}`, the signature being a base64
// HMAC-SHA512 of `{id}\n{expiry}` under the chosen key.
//
// This shape comes from Microsoft's published sample for generating the token
// by hand, NOT from a capture of Azure's own generateToken response. It is
// checkable without trusting us — the witness recomputes the HMAC from the key
// listKeys hands back — but the format itself is documentation-derived.
func gatewayToken(name string, expiry time.Time, key string) string {
	stamp := expiry.UTC().Format(tokenExpiryLayout)
	mac := hmac.New(sha512.New, []byte(key))
	mac.Write([]byte(name + "\n" + stamp))
	return name + "&" + stamp + "&" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// gatewayAPIRoute serves the associations that decide which APIs a gateway is
// allowed to serve.
func (h *Handler) gatewayAPIRoute(w http.ResponseWriter, r *http.Request, rt route, gateway model.Gateway) {
	switch len(rt.Tail) {
	case 3:
		h.gatewayAPICollection(w, r, gateway)
	case 4:
		h.gatewayAPIResource(w, r, gateway, gateway.ServiceID+"/apis/"+rt.Tail[3])
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", gateway.ID())
	}
}

func (h *Handler) gatewayAPICollection(w http.ResponseWriter, r *http.Request, gateway model.Gateway) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	ids, err := h.Store.ListGatewayAPIs(gateway.ID())
	if err != nil {
		h.storeError(w, err, gateway.ID())
		return
	}
	resources := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		api, err := h.Store.GetAPI(id)
		if err != nil {
			h.storeError(w, err, id)
			return
		}
		resources = append(resources, apiWire(api))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) gatewayAPIResource(w http.ResponseWriter, r *http.Request, gateway model.Gateway, apiID string) {
	switch r.Method {
	case http.MethodHead:
		attached, err := h.Store.GatewayAPIAttached(gateway.ID(), apiID)
		if err != nil {
			h.storeError(w, err, apiID)
			return
		}
		if !attached {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The API is not associated with this gateway.", apiID)
			return
		}
		api, err := h.Store.GetAPI(apiID)
		if err != nil {
			h.storeError(w, err, apiID)
			return
		}
		w.Header().Set("ETag", api.ETag)
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		// The API has to exist on the same service. An association with an API
		// nobody defined would put a route on the gateway that resolves to
		// nothing, and it would only be discovered by calling it.
		api, err := h.Store.GetAPI(apiID)
		if err != nil {
			h.storeError(w, err, apiID)
			return
		}
		if err := h.Store.AttachGatewayAPI(gateway.ID(), apiID); err != nil {
			h.storeError(w, err, apiID)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), apiID)
			return
		}
		writeResource(w, http.StatusCreated, apiWire(api), api.ETag)
	case http.MethodDelete:
		if err := h.Store.DetachGatewayAPI(gateway.ID(), apiID); err != nil {
			h.storeError(w, err, apiID)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), apiID)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

// gatewayHostnameRoute serves the hostnames a gateway answers on.
func (h *Handler) gatewayHostnameRoute(w http.ResponseWriter, r *http.Request, rt route, gateway model.Gateway) {
	switch len(rt.Tail) {
	case 3:
		h.gatewayHostnameCollection(w, r, gateway)
	case 4:
		h.gatewayHostnameResource(w, r, model.GatewayHostnameConfiguration{GatewayID: gateway.ID(), Name: rt.Tail[3]}, gateway.ServiceID)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", gateway.ID())
	}
}

func (h *Handler) gatewayHostnameCollection(w http.ResponseWriter, r *http.Request, gateway model.Gateway) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListGatewayHostnameConfigurations(gateway.ID())
	if err != nil {
		h.storeError(w, err, gateway.ID())
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, gatewayHostnameWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) gatewayHostnameResource(w http.ResponseWriter, r *http.Request, value model.GatewayHostnameConfiguration, serviceID string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetGatewayHostnameConfiguration(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, gatewayHostnameWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		h.gatewayHostnameUpsert(w, r, value, serviceID)
	case http.MethodDelete:
		if err := h.Store.DeleteGatewayHostnameConfiguration(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) gatewayHostnameUpsert(w http.ResponseWriter, r *http.Request, value model.GatewayHostnameConfiguration, serviceID string) {
	existing, existingErr := h.Store.GetGatewayHostnameConfiguration(value.ID())
	if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
		h.storeError(w, existingErr, value.ID())
		return
	}
	if r.Method == http.MethodPatch {
		if existingErr != nil {
			h.storeError(w, existingErr, value.ID())
			return
		}
		value = existing
	}
	var body struct {
		Properties struct {
			Hostname                   *string `json:"hostname"`
			CertificateID              *string `json:"certificateId"`
			NegotiateClientCertificate *bool   `json:"negotiateClientCertificate"`
			TLS10Enabled               *bool   `json:"tls10Enabled"`
			TLS11Enabled               *bool   `json:"tls11Enabled"`
			HTTP2Enabled               *bool   `json:"http2Enabled"`
		} `json:"properties"`
	}
	var document map[string]any
	if err := decodeDocument(r, &body, &document); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
		return
	}
	if body.Properties.Hostname != nil {
		value.Hostname = *body.Properties.Hostname
	}
	if body.Properties.CertificateID != nil {
		value.CertificateID = *body.Properties.CertificateID
	}
	if body.Properties.NegotiateClientCertificate != nil {
		value.NegotiateClientCertificate = *body.Properties.NegotiateClientCertificate
	}
	if body.Properties.TLS10Enabled != nil {
		value.TLS10Enabled = *body.Properties.TLS10Enabled
	}
	if body.Properties.TLS11Enabled != nil {
		value.TLS11Enabled = *body.Properties.TLS11Enabled
	}
	if body.Properties.HTTP2Enabled != nil {
		value.HTTP2Enabled = *body.Properties.HTTP2Enabled
	}
	if strings.TrimSpace(value.Hostname) == "" {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"properties.hostname is required.", "properties.hostname")
		return
	}
	// certificateId names a certificate entity on the same service. A hostname
	// pointing at a certificate nobody uploaded would present no chain at all,
	// so the reference is checked here rather than discovered at the first TLS
	// handshake.
	if value.CertificateID != "" {
		if _, err := h.Store.GetCertificate(certificateReference(serviceID, value.CertificateID)); err != nil {
			h.storeError(w, err, value.CertificateID)
			return
		}
	}
	value.Document = document
	cleanResourceDocument(value.Document)
	got, err := h.Store.UpsertGatewayHostnameConfiguration(value)
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	if err := h.activate(); err != nil {
		writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
		return
	}
	status := http.StatusOK
	if errors.Is(existingErr, store.ErrNotFound) {
		status = http.StatusCreated
	}
	writeResource(w, status, gatewayHostnameWire(got), got.ETag)
}

// certificateReference resolves a certificateId that may be written either as a
// bare certificate name or as a full ARM resource ID, which is what the portal
// and the SDK samples both emit.
func certificateReference(serviceID, value string) string {
	if index := strings.LastIndex(strings.ToLower(value), "/certificates/"); index >= 0 {
		return serviceID + "/certificates/" + value[index+len("/certificates/"):]
	}
	return serviceID + "/certificates/" + value
}

// gatewayCertificateAuthorityRoute serves per-gateway CA trust.
func (h *Handler) gatewayCertificateAuthorityRoute(w http.ResponseWriter, r *http.Request, rt route, gateway model.Gateway) {
	switch len(rt.Tail) {
	case 3:
		h.gatewayCertificateAuthorityCollection(w, r, gateway)
	case 4:
		h.gatewayCertificateAuthorityResource(w, r, model.GatewayCertificateAuthority{GatewayID: gateway.ID(), Name: rt.Tail[3]})
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", gateway.ID())
	}
}

func (h *Handler) gatewayCertificateAuthorityCollection(w http.ResponseWriter, r *http.Request, gateway model.Gateway) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListGatewayCertificateAuthorities(gateway.ID())
	if err != nil {
		h.storeError(w, err, gateway.ID())
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, gatewayCertificateAuthorityWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) gatewayCertificateAuthorityResource(w http.ResponseWriter, r *http.Request, value model.GatewayCertificateAuthority) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetGatewayCertificateAuthority(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, gatewayCertificateAuthorityWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		h.gatewayCertificateAuthorityUpsert(w, r, value)
	case http.MethodDelete:
		if err := h.Store.DeleteGatewayCertificateAuthority(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) gatewayCertificateAuthorityUpsert(w http.ResponseWriter, r *http.Request, value model.GatewayCertificateAuthority) {
	existing, existingErr := h.Store.GetGatewayCertificateAuthority(value.ID())
	if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
		h.storeError(w, existingErr, value.ID())
		return
	}
	if r.Method == http.MethodPatch {
		if existingErr != nil {
			h.storeError(w, existingErr, value.ID())
			return
		}
		value = existing
	}
	var body struct {
		Properties struct {
			IsTrusted *bool `json:"isTrusted"`
		} `json:"properties"`
	}
	var document map[string]any
	if err := decodeDocument(r, &body, &document); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
		return
	}
	if body.Properties.IsTrusted != nil {
		value.IsTrusted = *body.Properties.IsTrusted
	}
	value.Document = document
	cleanResourceDocument(value.Document)
	got, err := h.Store.UpsertGatewayCertificateAuthority(value)
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	status := http.StatusOK
	if errors.Is(existingErr, store.ErrNotFound) {
		status = http.StatusCreated
	}
	writeResource(w, status, gatewayCertificateAuthorityWire(got), got.ETag)
}

func gatewayWire(v model.Gateway) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/gateways"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	locationData, ok := properties["locationData"].(map[string]any)
	if !ok {
		locationData = map[string]any{}
		properties["locationData"] = locationData
	}
	locationData["name"] = v.LocationName
	if v.Description != "" {
		properties["description"] = v.Description
	} else {
		delete(properties, "description")
	}
	// The keys never appear on a GET. listKeys is the only way to read them,
	// exactly as with a subscription: a management read must not become a way
	// to harvest the credential that signs gateway tokens.
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
	return result
}

func gatewayHostnameWire(v model.GatewayHostnameConfiguration) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/gateways/hostnameConfigurations"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["hostname"] = v.Hostname
	properties["negotiateClientCertificate"] = v.NegotiateClientCertificate
	properties["tls10Enabled"] = v.TLS10Enabled
	properties["tls11Enabled"] = v.TLS11Enabled
	properties["http2Enabled"] = v.HTTP2Enabled
	if v.CertificateID != "" {
		properties["certificateId"] = v.CertificateID
	} else {
		delete(properties, "certificateId")
	}
	return result
}

func gatewayCertificateAuthorityWire(v model.GatewayCertificateAuthority) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/gateways/certificateAuthorities"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["isTrusted"] = v.IsTrusted
	return result
}
