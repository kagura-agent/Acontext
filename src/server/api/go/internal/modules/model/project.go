package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Project struct {
	ID                uuid.UUID         `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	SecretKeyHMAC     string            `gorm:"type:varchar(64);uniqueIndex;not null" json:"-"`
	SecretKeyHashPHC  string            `gorm:"type:varchar(255);not null" json:"-"`
	EncryptionEnabled bool              `gorm:"type:bool;not null;default:false" json:"encryption_enabled"`
	Configs           datatypes.JSONMap `gorm:"type:jsonb;index:idx_projects_configs,type:gin" swaggertype:"object" json:"configs"`

	// Key rotation state: non-nil when a rotation is in progress.
	// RotationEncryptedSecret holds the new secret encrypted with the old KEK (base64).
	// RotationNewHMAC holds the pre-computed HMAC of the new secret for finalizing.
	// RotationNewPHC holds the pre-computed PHC hash of the new secret for finalizing.
	RotationEncryptedSecret *string    `gorm:"type:text" json:"-"`
	RotationNewHMAC         *string    `gorm:"type:char(64)" json:"-"`
	RotationNewPHC          *string    `gorm:"type:varchar(255)" json:"-"`
	RotationStartedAt       *time.Time `gorm:"type:timestamptz" json:"-"`

	CreatedAt time.Time `gorm:"autoCreateTime;not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;not null;default:CURRENT_TIMESTAMP" json:"updated_at"`

	// Project <-> Session
	Sessions []Session `gorm:"constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"-"`

	// Project <-> Task
	Tasks []Task `gorm:"constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"-"`

	// Project <-> Metric
	Metrics []Metric `gorm:"constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"-"`

	// Project <-> AgentSkills
	AgentSkills []AgentSkills `gorm:"constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"-"`

	// Project <-> User
	Users []User `gorm:"constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"-"`

	// Project <-> SandboxLog
	SandboxLogs []SandboxLog `gorm:"constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"-"`
}

func (Project) TableName() string { return "projects" }
