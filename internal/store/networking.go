package store

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

// UpsertPrivateEndpointConnection creates or replaces one connection.
func (s *Store) UpsertPrivateEndpointConnection(v model.PrivateEndpointConnection) (model.PrivateEndpointConnection, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO private_endpoint_connections
          (id, service_id, name, status, description, actions_required, endpoint_id, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,
          description=excluded.description, actions_required=excluded.actions_required,
          endpoint_id=excluded.endpoint_id, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.Status, v.Description, v.ActionsRequired, v.EndpointID, string(document), v.ETag)
	return v, err
}

// GetPrivateEndpointConnection finds one connection.
func (s *Store) GetPrivateEndpointConnection(id string) (model.PrivateEndpointConnection, error) {
	var v model.PrivateEndpointConnection
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, status, description, actions_required, endpoint_id, document_json, etag
	        FROM private_endpoint_connections WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.Status, &v.Description, &v.ActionsRequired, &v.EndpointID, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PrivateEndpointConnection{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListPrivateEndpointConnections returns a service's connections in stable ID
// order.
func (s *Store) ListPrivateEndpointConnections(serviceID string) ([]model.PrivateEndpointConnection, error) {
	rows, err := s.db.Query(`SELECT service_id, name, status, description, actions_required, endpoint_id, document_json, etag
        FROM private_endpoint_connections WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.PrivateEndpointConnection, 0)
	for rows.Next() {
		var v model.PrivateEndpointConnection
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.Status, &v.Description, &v.ActionsRequired, &v.EndpointID, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeletePrivateEndpointConnection removes one connection.
func (s *Store) DeletePrivateEndpointConnection(id string) error {
	return deleteScopedResource(s.db, "private_endpoint_connections", id)
}
