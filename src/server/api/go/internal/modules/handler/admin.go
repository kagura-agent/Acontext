package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/memodb-io/Acontext/internal/config"
	"github.com/memodb-io/Acontext/internal/infra/blob"
	encryptionpkg "github.com/memodb-io/Acontext/internal/infra/crypto"
	"github.com/memodb-io/Acontext/internal/middleware"
	"github.com/memodb-io/Acontext/internal/modules/model"
	"github.com/memodb-io/Acontext/internal/modules/repo"
	"github.com/memodb-io/Acontext/internal/modules/serializer"
	"github.com/memodb-io/Acontext/internal/modules/service"
	"github.com/memodb-io/Acontext/internal/pkg/utils/secrets"
	"github.com/memodb-io/Acontext/internal/pkg/utils/tokens"
	"gorm.io/gorm"
)

// generateRotationSecret generates a random 32-byte secret encoded as base64url (same format as project service).
func generateRotationSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type AdminHandler struct {
	projectSvc       service.ProjectService
	projectRepo      repo.ProjectRepo
	s3               *blob.S3Deps
	assetRefRepo     repo.AssetReferenceRepo
	db               *gorm.DB
	cfg              *config.Config
}

func NewAdminHandler(projectSvc service.ProjectService, projectRepo repo.ProjectRepo, s3 *blob.S3Deps, assetRefRepo repo.AssetReferenceRepo, db *gorm.DB, cfg *config.Config) *AdminHandler {
	return &AdminHandler{
		projectSvc:       projectSvc,
		projectRepo:      projectRepo,
		s3:               s3,
		assetRefRepo:     assetRefRepo,
		db:               db,
		cfg:              cfg,
	}
}

type CreateProjectReq struct {
	Configs map[string]interface{} `json:"configs,omitempty"`
}

// CreateProject godoc
//
//	@Summary		Create a new project
//	@Description	Create a new project with a randomly generated secret key
//	@Tags			admin
//	@Accept			json
//	@Produce		json
//	@Param			body	body		CreateProjectReq	false	"Project configuration"
//	@Success		200		{object}	serializer.Response{data=service.CreateProjectOutput}
//	@Failure		400		{object}	serializer.Response
//	@Failure		500		{object}	serializer.Response
//	@Router			/admin/v1/project [post]
func (h *AdminHandler) CreateProject(c *gin.Context) {
	var req CreateProjectReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("", err))
		return
	}

	// Set default value to empty map if configs is nil
	if req.Configs == nil {
		req.Configs = make(map[string]interface{})
	}

	output, err := h.projectSvc.Create(c.Request.Context(), req.Configs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("", err))
		return
	}

	c.JSON(http.StatusOK, serializer.Response{Data: output})
}

// DeleteProject godoc
//
//	@Summary		Delete a project
//	@Description	Delete a project by ID
//	@Tags			admin
//	@Accept			json
//	@Produce		json
//	@Param			project_id	path		string	true	"Project ID"	format(uuid)
//	@Success		200			{object}	serializer.Response
//	@Failure		400			{object}	serializer.Response
//	@Failure		500			{object}	serializer.Response
//	@Router			/admin/v1/project/{project_id} [delete]
func (h *AdminHandler) DeleteProject(c *gin.Context) {
	projectIDStr := c.Param("project_id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("invalid project id", err))
		return
	}

	if err := h.projectSvc.Delete(c.Request.Context(), projectID); err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("", err))
		return
	}

	c.JSON(http.StatusOK, serializer.Response{Msg: "project deleted"})
}

// UpdateProjectSecretKey godoc
//
//	@Summary		Update project secret key
//	@Description	Generate a new secret key for a project
//	@Tags			admin
//	@Accept			json
//	@Produce		json
//	@Param			project_id	path		string	true	"Project ID"	format(uuid)
//	@Success		200			{object}	serializer.Response{data=service.UpdateSecretKeyOutput}
//	@Failure		400			{object}	serializer.Response
//	@Failure		500			{object}	serializer.Response
//	@Router			/admin/v1/project/{project_id}/secret_key [put]
func (h *AdminHandler) UpdateProjectSecretKey(c *gin.Context) {
	projectIDStr := c.Param("project_id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("invalid project id", err))
		return
	}

	output, err := h.projectSvc.UpdateSecretKey(c.Request.Context(), projectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("", err))
		return
	}

	c.JSON(http.StatusOK, serializer.Response{Data: output})
}

// AnalyzeProjectUsages godoc
//
//	@Summary		Analyze project usages
//	@Description	Get usage analytics for a project
//	@Tags			admin
//	@Accept			json
//	@Produce		json
//	@Param			project_id		path		string	true	"Project ID"								format(uuid)
//	@Param			interval_days	query		int		false	"Number of days to analyze (default: 30)"	default(30)
//	@Param			fields			query		string	false	"Comma-separated list of fields to fetch (empty = all)"
//	@Success		200				{object}	serializer.Response
//	@Router			/admin/v1/project/{project_id}/usages [get]
func (h *AdminHandler) AnalyzeProjectUsages(c *gin.Context) {
	projectIDStr := c.Param("project_id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("invalid project id", err))
		return
	}

	// Get interval_days from query parameter, default to 30
	intervalDaysStr := c.DefaultQuery("interval_days", "30")
	intervalDays, err := strconv.Atoi(intervalDaysStr)
	if err != nil || intervalDays <= 0 {
		intervalDays = 30
	}

	// Parse fields query parameter
	var fields []string
	if fieldsStr := c.Query("fields"); fieldsStr != "" {
		for _, f := range strings.Split(fieldsStr, ",") {
			if trimmed := strings.TrimSpace(f); trimmed != "" {
				fields = append(fields, trimmed)
			}
		}
	}

	output, err := h.projectSvc.AnalyzeUsages(c.Request.Context(), projectID, intervalDays, fields)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("", err))
		return
	}

	c.JSON(http.StatusOK, serializer.Response{Data: output})
}

// AnalyzeProjectStatistics godoc
//
//	@Summary		Analyze project statistics
//	@Description	Get statistics for a project
//	@Tags			admin
//	@Accept			json
//	@Produce		json
//	@Param			project_id	path		string	true	"Project ID"	format(uuid)
//	@Success		200			{object}	serializer.Response
//	@Router			/admin/v1/project/{project_id}/statistics [get]
func (h *AdminHandler) AnalyzeProjectStatistics(c *gin.Context) {
	projectIDStr := c.Param("project_id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("invalid project id", err))
		return
	}

	output, err := h.projectSvc.AnalyzeStatistics(c.Request.Context(), projectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("", err))
		return
	}

	c.JSON(http.StatusOK, serializer.Response{Data: output})
}

// AnalyzeProjectMetrics godoc
//
//	@Summary		Analyze project metrics
//	@Description	Get metrics for a project by querying Jaeger API with project_id filter
//	@Tags			admin
//	@Accept			json
//	@Produce		json
//	@Param			project_id	path		string	true	"Project ID"	format(uuid)
//	@Success		200			{object}	serializer.Response
//	@Router			/admin/v1/project/{project_id}/metrics [get]
func (h *AdminHandler) AnalyzeProjectMetrics(c *gin.Context) {
	projectIDStr := c.Param("project_id")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("invalid project id", err))
		return
	}

	resp, err := h.projectSvc.AnalyzeMetrics(
		c.Request.Context(),
		projectID,
		c.Request.URL.String(),
		c.Request.Method,
		c.Request.Header,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to query Jaeger", err))
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to read response", err))
		return
	}

	// Only forward safe response headers from Jaeger
	safeHeaders := map[string]bool{
		"Content-Type":     true,
		"Content-Encoding": true,
	}
	for key, values := range resp.Header {
		if safeHeaders[http.CanonicalHeaderKey(key)] {
			for _, value := range values {
				c.Header(key, value)
			}
		}
	}

	// Return the response from Jaeger
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

// EncryptProject encrypts all existing S3 data for a project and enables encryption.
// Requires project API key as Bearer auth (uses ProjectAuth middleware).
func (h *AdminHandler) EncryptProject(c *gin.Context) {
	project, ok := c.MustGet("project").(*model.Project)
	if !ok {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("", fmt.Errorf("project not found")))
		return
	}

	userKEK := middleware.GetUserKEK(c)
	if userKEK == nil {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("", fmt.Errorf("API key required to derive encryption key")))
		return
	}

	if project.EncryptionEnabled {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("project encryption is already enabled", nil))
		return
	}

	// Set encryption_enabled = true FIRST for crash safety.
	// If we crash after this but before encrypting all objects, reads will use KEK
	// and unencrypted objects pass through decryption gracefully. Retry re-encrypts
	// remaining objects (EncryptObject is idempotent).
	if err := h.db.WithContext(c.Request.Context()).Model(&model.Project{}).
		Where("id = ?", project.ID).
		Update("encryption_enabled", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to update project", err))
		return
	}

	// Enumerate all S3 keys for this project
	s3Keys, err := h.assetRefRepo.ListS3KeysByProject(c.Request.Context(), project.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to list S3 keys", err))
		return
	}

	// Encrypt each object (idempotent — skips already-encrypted objects)
	for _, key := range s3Keys {
		if err := h.s3.EncryptObject(c.Request.Context(), key, userKEK); err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr(fmt.Sprintf("failed to encrypt object %s", key), err))
			return
		}
	}

	c.JSON(http.StatusOK, serializer.Response{Msg: "encryption enabled"})
}

// DecryptProject decrypts all existing S3 data for a project and disables encryption.
// Requires project API key as Bearer auth (uses ProjectAuth middleware).
func (h *AdminHandler) DecryptProject(c *gin.Context) {
	project, ok := c.MustGet("project").(*model.Project)
	if !ok {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("", fmt.Errorf("project not found")))
		return
	}

	userKEK := middleware.GetUserKEK(c)
	if userKEK == nil {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("", fmt.Errorf("API key required to derive encryption key")))
		return
	}

	if !project.EncryptionEnabled {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("project encryption is not enabled", nil))
		return
	}

	// Enumerate all S3 keys for this project
	s3Keys, err := h.assetRefRepo.ListS3KeysByProject(c.Request.Context(), project.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to list S3 keys", err))
		return
	}

	// Decrypt each object FIRST, then clear the flag (idempotent — skips already-decrypted).
	// If we crash mid-decrypt, flag stays true so reads use KEK, which works on
	// both encrypted and already-decrypted objects. Retry re-decrypts remaining.
	for _, key := range s3Keys {
		if err := h.s3.DecryptObject(c.Request.Context(), key, userKEK); err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr(fmt.Sprintf("failed to decrypt object %s", key), err))
			return
		}
	}

	// Set encryption_enabled = false AFTER all objects are decrypted
	if err := h.db.WithContext(c.Request.Context()).Model(&model.Project{}).
		Where("id = ?", project.ID).
		Update("encryption_enabled", false).Error; err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to update project", err))
		return
	}

	c.JSON(http.StatusOK, serializer.Response{Msg: "encryption disabled"})
}

// UpdateProjectSecretKeyWithRewrap rotates the project API key with DEK re-wrapping for encrypted projects.
// Requires the old project API key as Bearer auth (uses ProjectAuth middleware).
//
// The rotation is crash-safe: DEKs are rewrapped BEFORE the DB key is committed.
// If a crash occurs mid-rewrap, the old key is still active and the caller can retry.
// The flow is:
//  1. Generate new credentials + store rotation state (encrypted new secret in DB)
//  2. Rewrap all S3 DEKs (idempotent — already-rewrapped objects are skipped)
//  3. Atomically commit new key + clear rotation state
func (h *AdminHandler) UpdateProjectSecretKeyWithRewrap(c *gin.Context) {
	project, ok := c.MustGet("project").(*model.Project)
	if !ok {
		c.JSON(http.StatusBadRequest, serializer.ParamErr("", fmt.Errorf("project not found")))
		return
	}

	oldUserKEK := middleware.GetUserKEK(c)

	// For non-encrypted projects, just rotate the DB key directly (no DEK concern).
	if !project.EncryptionEnabled || oldUserKEK == nil {
		output, err := h.projectSvc.UpdateSecretKey(c.Request.Context(), project.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to generate new key", err))
			return
		}
		c.JSON(http.StatusOK, serializer.Response{Data: output})
		return
	}

	// --- Encrypted project: crash-safe 3-phase rotation ---
	ctx := c.Request.Context()
	pepper := h.cfg.Root.SecretPepper
	prefix := h.cfg.Root.ProjectBearerTokenPrefix

	var newSecret string
	var newUserKEK []byte

	// Check for pending rotation state (resume after crash)
	if project.RotationEncryptedSecret != nil {
		// Decrypt the stored new secret using the old KEK
		encMeta := &encryptionpkg.EncryptedMeta{
			Algo:           "AES-256-GCM",
			UserWrappedDEK: *project.RotationEncryptedSecret,
		}
		// The encrypted secret is stored as: encrypted(newSecret) using oldKEK as wrapper
		// We stored it via EncryptData, so decrypt with the same KEK
		// Actually, we used WrapDEK directly — the "encrypted secret" is base64(WrapDEK(oldKEK, secretBytes))
		_ = encMeta // unused in this path, we use direct unwrap below

		wrappedBytes, err := encryptionpkg.DecodeBase64(*project.RotationEncryptedSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to decode rotation state", err))
			return
		}
		secretBytes, err := encryptionpkg.UnwrapDEK(oldUserKEK, wrappedBytes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to decrypt rotation state", err))
			return
		}
		newSecret = string(secretBytes)
	} else {
		// Phase 1: Generate new secret and persist rotation state
		var err error
		newSecret, err = generateRotationSecret()
		if err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to generate secret", err))
			return
		}

		// Encrypt the new secret with old KEK for crash-safe storage
		wrappedSecret, err := encryptionpkg.WrapDEK(oldUserKEK, []byte(newSecret))
		if err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to encrypt rotation state", err))
			return
		}
		encryptedSecretB64 := encryptionpkg.EncodeBase64(wrappedSecret)

		// Pre-compute new HMAC and PHC
		newHMAC := tokens.HMAC256Hex(pepper, newSecret)
		newPHC, err := secrets.HashSecret(newSecret, pepper)
		if err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to hash new secret", err))
			return
		}

		// Store rotation state (old key still active in DB)
		if err := h.projectRepo.SetRotationState(ctx, project.ID, encryptedSecretB64, newHMAC, newPHC); err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to store rotation state", err))
			return
		}
	}

	// Derive new KEK
	var err error
	newUserKEK, err = encryptionpkg.DeriveUserKEK(newSecret, pepper)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to derive new KEK", err))
		return
	}

	// Phase 2: Rewrap all DEKs (idempotent — skips already-rewrapped objects)
	s3Keys, err := h.assetRefRepo.ListS3KeysByProject(ctx, project.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to list S3 keys", err))
		return
	}

	for _, key := range s3Keys {
		if err := h.s3.RewrapObjectDEK(ctx, key, oldUserKEK, newUserKEK); err != nil {
			c.JSON(http.StatusInternalServerError, serializer.DBErr(fmt.Sprintf("failed to rewrap DEK for %s", key), err))
			return
		}
	}

	// Phase 3: Atomically commit new credentials and clear rotation state
	if err := h.projectRepo.FinalizeRotation(ctx, project.ID); err != nil {
		c.JSON(http.StatusInternalServerError, serializer.DBErr("failed to finalize rotation", err))
		return
	}

	c.JSON(http.StatusOK, serializer.Response{
		Data: service.UpdateSecretKeyOutput{SecretKey: prefix + newSecret},
	})
}

