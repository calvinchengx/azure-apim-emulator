package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

// Self-hosted gateway persistence: the registration, the APIs it is allowed to
// serve, the hostnames it answers on, and the certificate authorities it
// trusts.

// UpsertGateway creates or replaces one gateway registration.
//
// The keys are written only when the caller supplied them, so an update that
// carries no keys keeps the ones already issued. A PUT that silently reissued
// them would revoke every token minted from the old pair, which is a
// configuration change nobody asked for.
func (s *Store) UpsertGateway(v model.Gateway) (model.Gateway, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO gateways (id, service_id, name, location_name, description, primary_key, secondary_key, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET location_name=excluded.location_name,
          description=excluded.description, primary_key=excluded.primary_key, secondary_key=excluded.secondary_key,
          document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.LocationName, v.Description, v.PrimaryKey, v.SecondaryKey, string(document), v.ETag)
	return v, err
}

// GetGateway finds one gateway registration.
func (s *Store) GetGateway(id string) (model.Gateway, error) {
	var v model.Gateway
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, location_name, description, primary_key, secondary_key, document_json, etag
	        FROM gateways WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.LocationName, &v.Description, &v.PrimaryKey, &v.SecondaryKey, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Gateway{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListGateways returns a service's gateways in stable ID order.
func (s *Store) ListGateways(serviceID string) ([]model.Gateway, error) {
	rows, err := s.db.Query(`SELECT service_id, name, location_name, description, primary_key, secondary_key, document_json, etag
        FROM gateways WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Gateway, 0)
	for rows.Next() {
		var v model.Gateway
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.LocationName, &v.Description, &v.PrimaryKey, &v.SecondaryKey, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteGateway removes a gateway and, by cascade, its API associations,
// hostname configurations and certificate authorities. Deleting the
// registration is what takes a self-hosted gateway out of service, so nothing
// it was configured with may outlive it.
func (s *Store) DeleteGateway(id string) error {
	return deleteScopedResource(s.db, "gateways", id)
}

// AttachGatewayAPI associates an API with a gateway.
//
// The association is the gateway's whole authority: an API that is not
// associated is not served there, so this is a runtime decision recorded
// through the management plane rather than a label.
func (s *Store) AttachGatewayAPI(gatewayID, apiID string) error {
	_, err := s.db.Exec(`INSERT INTO gateway_apis (gateway_id, api_id) VALUES (?, ?)
        ON CONFLICT(gateway_id, api_id) DO NOTHING`, gatewayID, apiID)
	return err
}

// DetachGatewayAPI removes an association, reporting ErrNotFound when the API
// was not associated in the first place. Azure distinguishes the two, and a
// caller that deletes a link it never created should learn that rather than
// receive a success it can act on.
func (s *Store) DetachGatewayAPI(gatewayID, apiID string) error {
	result, err := s.db.Exec(`DELETE FROM gateway_apis WHERE lower(gateway_id)=lower(?) AND lower(api_id)=lower(?)`, gatewayID, apiID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// ListGatewayAPIs returns the API IDs associated with one gateway, in stable
// order.
func (s *Store) ListGatewayAPIs(gatewayID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT api_id FROM gateway_apis WHERE lower(gateway_id)=lower(?) ORDER BY api_id`, gatewayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// GatewayAPIAttached reports whether one API is associated with one gateway.
func (s *Store) GatewayAPIAttached(gatewayID, apiID string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM gateway_apis WHERE lower(gateway_id)=lower(?) AND lower(api_id)=lower(?)`,
		gatewayID, apiID).Scan(&count)
	return count > 0, err
}

// UpsertGatewayHostnameConfiguration creates or replaces one hostname a gateway
// answers on.
func (s *Store) UpsertGatewayHostnameConfiguration(v model.GatewayHostnameConfiguration) (model.GatewayHostnameConfiguration, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO gateway_hostname_configurations
          (id, gateway_id, name, hostname, certificate_id, negotiate_client_certificate, tls10_enabled, tls11_enabled, http2_enabled, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET hostname=excluded.hostname,
          certificate_id=excluded.certificate_id, negotiate_client_certificate=excluded.negotiate_client_certificate,
          tls10_enabled=excluded.tls10_enabled, tls11_enabled=excluded.tls11_enabled, http2_enabled=excluded.http2_enabled,
          document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.GatewayID, v.Name, v.Hostname, v.CertificateID, v.NegotiateClientCertificate,
		v.TLS10Enabled, v.TLS11Enabled, v.HTTP2Enabled, string(document), v.ETag)
	return v, err
}

// GetGatewayHostnameConfiguration finds one hostname configuration.
func (s *Store) GetGatewayHostnameConfiguration(id string) (model.GatewayHostnameConfiguration, error) {
	var v model.GatewayHostnameConfiguration
	var document string
	err := s.db.QueryRow(`SELECT gateway_id, name, hostname, certificate_id, negotiate_client_certificate,
	          tls10_enabled, tls11_enabled, http2_enabled, document_json, etag
	        FROM gateway_hostname_configurations WHERE lower(id)=lower(?)`, id).
		Scan(&v.GatewayID, &v.Name, &v.Hostname, &v.CertificateID, &v.NegotiateClientCertificate,
			&v.TLS10Enabled, &v.TLS11Enabled, &v.HTTP2Enabled, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.GatewayHostnameConfiguration{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListGatewayHostnameConfigurations returns a gateway's hostnames in stable ID
// order.
func (s *Store) ListGatewayHostnameConfigurations(gatewayID string) ([]model.GatewayHostnameConfiguration, error) {
	rows, err := s.db.Query(`SELECT gateway_id, name, hostname, certificate_id, negotiate_client_certificate,
	          tls10_enabled, tls11_enabled, http2_enabled, document_json, etag
        FROM gateway_hostname_configurations WHERE lower(gateway_id)=lower(?) ORDER BY id`, gatewayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.GatewayHostnameConfiguration, 0)
	for rows.Next() {
		var v model.GatewayHostnameConfiguration
		var document string
		if err := rows.Scan(&v.GatewayID, &v.Name, &v.Hostname, &v.CertificateID, &v.NegotiateClientCertificate,
			&v.TLS10Enabled, &v.TLS11Enabled, &v.HTTP2Enabled, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteGatewayHostnameConfiguration removes one hostname configuration.
func (s *Store) DeleteGatewayHostnameConfiguration(id string) error {
	return deleteScopedResource(s.db, "gateway_hostname_configurations", id)
}

// UpsertGatewayCertificateAuthority creates or replaces one gateway CA trust
// record.
func (s *Store) UpsertGatewayCertificateAuthority(v model.GatewayCertificateAuthority) (model.GatewayCertificateAuthority, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO gateway_certificate_authorities (id, gateway_id, name, is_trusted, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET is_trusted=excluded.is_trusted,
          document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.GatewayID, v.Name, v.IsTrusted, string(document), v.ETag)
	return v, err
}

// GetGatewayCertificateAuthority finds one gateway CA trust record.
func (s *Store) GetGatewayCertificateAuthority(id string) (model.GatewayCertificateAuthority, error) {
	var v model.GatewayCertificateAuthority
	var document string
	err := s.db.QueryRow(`SELECT gateway_id, name, is_trusted, document_json, etag
	        FROM gateway_certificate_authorities WHERE lower(id)=lower(?)`, id).
		Scan(&v.GatewayID, &v.Name, &v.IsTrusted, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.GatewayCertificateAuthority{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListGatewayCertificateAuthorities returns a gateway's CA trust records in
// stable ID order.
func (s *Store) ListGatewayCertificateAuthorities(gatewayID string) ([]model.GatewayCertificateAuthority, error) {
	rows, err := s.db.Query(`SELECT gateway_id, name, is_trusted, document_json, etag
        FROM gateway_certificate_authorities WHERE lower(gateway_id)=lower(?) ORDER BY id`, gatewayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.GatewayCertificateAuthority, 0)
	for rows.Next() {
		var v model.GatewayCertificateAuthority
		var document string
		if err := rows.Scan(&v.GatewayID, &v.Name, &v.IsTrusted, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteGatewayCertificateAuthority removes one gateway CA trust record.
func (s *Store) DeleteGatewayCertificateAuthority(id string) error {
	return deleteScopedResource(s.db, "gateway_certificate_authorities", id)
}

// GatewayNameReserved reports whether a gateway ID is one Azure keeps for
// itself. `managed` names the built-in gateway that every service already has,
// so a registration under that name would be a second thing answering to the
// name of the first.
func GatewayNameReserved(name string) bool {
	return strings.EqualFold(name, "managed")
}
