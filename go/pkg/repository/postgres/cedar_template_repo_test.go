package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"stratium/pkg/models"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

func setupCedarTemplateRepoTest(t *testing.T) (*CedarTemplateRepository, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := NewCedarTemplateRepository(sqlxDB)
	return repo, mock, func() { db.Close() }
}

func TestCedarTemplateRepository_Create(t *testing.T) {
	repo, mock, cleanup := setupCedarTemplateRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()
	template := &models.CedarTemplate{
		ID:              uuid.New(),
		Name:            "user-access",
		Description:     "User access template",
		TemplateContent: `permit(principal == ?principal, action, resource == ?resource);`,
		Namespace:       "Acme",
		CreatedAt:       now,
		UpdatedAt:       now,
		CreatedBy:       "admin",
		UpdatedBy:       "admin",
	}

	mock.ExpectExec("INSERT INTO cedar_templates").
		WithArgs(
			template.ID, template.Name, template.Description,
			template.TemplateContent, template.SchemaID,
			template.Namespace, template.CreatedAt, template.UpdatedAt,
			template.CreatedBy, template.UpdatedBy,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.CreateTemplate(ctx, template)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarTemplateRepository_GetByID(t *testing.T) {
	repo, mock, cleanup := setupCedarTemplateRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	templateID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "template_content", "schema_id",
		"namespace", "created_at", "updated_at", "created_by", "updated_by",
	}).AddRow(
		templateID, "user-access", "Template", `permit(principal == ?principal, action, resource);`,
		nil, "Acme", now, now, "admin", "admin",
	)

	mock.ExpectQuery("SELECT .+ FROM cedar_templates WHERE id = \\$1").
		WithArgs(templateID).
		WillReturnRows(rows)

	template, err := repo.GetTemplateByID(ctx, templateID)
	assert.NoError(t, err)
	assert.Equal(t, templateID, template.ID)
	assert.Equal(t, "Acme", template.Namespace)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarTemplateRepository_GetByID_NotFound(t *testing.T) {
	repo, mock, cleanup := setupCedarTemplateRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	templateID := uuid.New()

	mock.ExpectQuery("SELECT .+ FROM cedar_templates WHERE id = \\$1").
		WithArgs(templateID).
		WillReturnError(sql.ErrNoRows)

	_, err := repo.GetTemplateByID(ctx, templateID)
	assert.ErrorIs(t, err, models.ErrCedarTemplateNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarTemplateRepository_Delete(t *testing.T) {
	repo, mock, cleanup := setupCedarTemplateRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	templateID := uuid.New()

	mock.ExpectExec("DELETE FROM cedar_templates WHERE id = \\$1").
		WithArgs(templateID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.DeleteTemplate(ctx, templateID)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarTemplateRepository_Delete_NotFound(t *testing.T) {
	repo, mock, cleanup := setupCedarTemplateRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	templateID := uuid.New()

	mock.ExpectExec("DELETE FROM cedar_templates WHERE id = \\$1").
		WithArgs(templateID).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.DeleteTemplate(ctx, templateID)
	assert.ErrorIs(t, err, models.ErrCedarTemplateNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarTemplateRepository_CreateLinkedPolicy(t *testing.T) {
	repo, mock, cleanup := setupCedarTemplateRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()
	link := &models.CedarLinkedPolicy{
		ID:              uuid.New(),
		TemplateID:      uuid.New(),
		PolicyID:        uuid.New(),
		PrincipalEntity: `Acme::User::"alice"`,
		ResourceEntity:  `Acme::Resource::"doc-1"`,
		CreatedAt:       now,
		CreatedBy:       "admin",
	}

	mock.ExpectExec("INSERT INTO cedar_linked_policies").
		WithArgs(
			link.ID, link.TemplateID, link.PolicyID,
			link.PrincipalEntity, link.ResourceEntity,
			link.CreatedAt, link.CreatedBy,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.CreateLinkedPolicy(ctx, link)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarTemplateRepository_ListLinkedPolicies(t *testing.T) {
	repo, mock, cleanup := setupCedarTemplateRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	templateID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "template_id", "policy_id", "principal_entity", "resource_entity", "created_at", "created_by",
	}).AddRow(
		uuid.New(), templateID, uuid.New(), `Acme::User::"alice"`, `Acme::Resource::"doc-1"`, now, "admin",
	).AddRow(
		uuid.New(), templateID, uuid.New(), `Acme::User::"bob"`, `Acme::Resource::"doc-2"`, now, "admin",
	)

	mock.ExpectQuery("SELECT .+ FROM cedar_linked_policies WHERE template_id = \\$1").
		WithArgs(templateID).
		WillReturnRows(rows)

	links, err := repo.ListLinkedPolicies(ctx, templateID)
	assert.NoError(t, err)
	assert.Len(t, links, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}
