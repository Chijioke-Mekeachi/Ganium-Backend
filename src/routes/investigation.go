package routes

import (
	"net/http"
	"time"

	"ganium/internal/investigation"
	"ganium/pkg/types"

	"github.com/gin-gonic/gin"
)

// ============================================================
// REQUEST MODEL
// ============================================================

// InvestigateRequest represents a security investigation request.
type InvestigateRequest struct {
	Target          string `json:"target" example:"https://example.com"`
	TargetType      string `json:"target_type" example:"url"`
	CaseID          string `json:"case_id" example:"CASE-12345"`
	Network         string `json:"network" example:"ethereum"`
	Source          string `json:"source" example:"user"`
	InvestigationID string `json:"investigation_id" example:"INV-12345"`
}

// ============================================================
// INVESTIGATION
// ============================================================

// InvestigateRoute godoc
// @Summary Run security investigation
// @Description Runs the Ganium security investigation pipeline against a target.
// @Tags Investigation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body InvestigateRequest true "Investigation request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/investigate [post]
func InvestigateRoute(c *gin.Context) {
	var payload InvestigateRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	if payload.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "target is required",
		})
		return
	}

	result, err := investigation.Default().Investigate(
		c.Request.Context(),
		investigation.Request{
			InvestigationID: payload.InvestigationID,
			CaseID:          payload.CaseID,
			TargetType:      types.TargetType(payload.TargetType),
			Target:          payload.Target,
			Network:         payload.Network,
			Source:          payload.Source,
		},
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"investigation_id": result.Evidence.InvestigationID,
		"case_id":          result.Evidence.CaseID,
		"evidence":         result.Evidence,
		"assessment":       result.Assessment,
		"completed_at":     time.Now().UTC(),
	})
}
