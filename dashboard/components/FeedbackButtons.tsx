/**
 * Feedback Buttons Component
 * Allows users to mark findings as true/false positives for learning
 */

import React, { useState } from 'react';
import {
  Button,
  ButtonGroup,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Slider,
  Typography,
  Box,
  Chip,
  Alert,
  FormControlLabel,
  Switch,
  CircularProgress,
  Tooltip,
  IconButton,
  Menu,
  MenuItem,
  Stack
} from '@mui/material';
import {
  ThumbUp,
  ThumbDown,
  QuestionMark,
  CheckCircle,
  Cancel,
  Info,
  Psychology,
  TrendingUp,
  TrendingDown,
  Shield,
  Group,
  Person,
  Public,
  Lock
} from '@mui/icons-material';
import { Finding } from '../types/findings';
import { useAuth } from '../hooks/useAuth';
import { useCredits } from '../hooks/useCredits';

interface FeedbackButtonsProps {
  finding: Finding;
  onFeedbackSubmit?: (feedback: FeedbackData) => void;
  showDetailed?: boolean;
  teamId?: string;
}

interface FeedbackData {
  findingId: string;
  feedbackType: 'true_positive' | 'false_positive' | 'uncertain';
  confidence: number;
  reason?: string;
  shareWithTeam: boolean;
  suppressionScope?: 'personal' | 'team' | 'project';
}

interface FeedbackStats {
  totalFeedback: number;
  truePositives: number;
  falsePositives: number;
  uncertain: number;
  consensus?: number;
}

export const FeedbackButtons: React.FC<FeedbackButtonsProps> = ({
  finding,
  onFeedbackSubmit,
  showDetailed = false,
  teamId
}) => {
  const { user } = useAuth();
  const { balance } = useCredits();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedType, setSelectedType] = useState<'true_positive' | 'false_positive' | 'uncertain' | null>(null);
  const [confidence, setConfidence] = useState(80);
  const [reason, setReason] = useState('');
  const [shareWithTeam, setShareWithTeam] = useState(false);
  const [suppressionScope, setSuppressionScope] = useState<'personal' | 'team' | 'project'>('personal');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [feedbackStats, setFeedbackStats] = useState<FeedbackStats | null>(null);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  // Check if user has already provided feedback
  const [userFeedback, setUserFeedback] = useState<FeedbackData | null>(null);

  const handleFeedbackClick = (type: 'true_positive' | 'false_positive' | 'uncertain') => {
    setSelectedType(type);
    if (showDetailed) {
      setDialogOpen(true);
    } else {
      // Quick feedback - submit immediately with default confidence
      submitFeedback(type, 80, '', false, 'personal');
    }
  };

  const submitFeedback = async (
    type: 'true_positive' | 'false_positive' | 'uncertain',
    conf: number,
    feedbackReason: string,
    share: boolean,
    scope: 'personal' | 'team' | 'project'
  ) => {
    setLoading(true);
    try {
      const response = await fetch('/api/interactive/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          finding_id: finding.id,
          feedback_type: type,
          confidence: conf / 100,
          reason: feedbackReason || undefined,
          share_with_team: share,
          team_id: share ? teamId : undefined,
          suppression_scope: type === 'false_positive' ? scope : undefined
        })
      });

      if (!response.ok) throw new Error('Failed to submit feedback');

      const data = await response.json();
      
      const feedbackData: FeedbackData = {
        findingId: finding.id,
        feedbackType: type,
        confidence: conf,
        reason: feedbackReason,
        shareWithTeam: share,
        suppressionScope: scope
      };

      setUserFeedback(feedbackData);
      setSubmitted(true);
      setDialogOpen(false);
      
      // Update stats if available
      if (data.stats) {
        setFeedbackStats(data.stats);
      }

      if (onFeedbackSubmit) {
        onFeedbackSubmit(feedbackData);
      }

      // Show success message
      setTimeout(() => setSubmitted(false), 3000);

    } catch (error) {
      console.error('Failed to submit feedback:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDialogSubmit = () => {
    if (selectedType) {
      submitFeedback(selectedType, confidence, reason, shareWithTeam, suppressionScope);
    }
  };

  const handleStatsClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
    // Load feedback statistics
    loadFeedbackStats();
  };

  const loadFeedbackStats = async () => {
    try {
      const response = await fetch(`/api/interactive/feedback/stats/${finding.pattern_type}/${finding.rule}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        const stats = await response.json();
        setFeedbackStats(stats);
      }
    } catch (error) {
      console.error('Failed to load feedback stats:', error);
    }
  };

  const getFeedbackIcon = (type: string) => {
    switch (type) {
      case 'true_positive':
        return <ThumbUp color="error" />;
      case 'false_positive':
        return <ThumbDown color="success" />;
      case 'uncertain':
        return <QuestionMark color="warning" />;
      default:
        return null;
    }
  };

  const getSuppressionScopeIcon = (scope: string) => {
    switch (scope) {
      case 'personal':
        return <Person fontSize="small" />;
      case 'team':
        return <Group fontSize="small" />;
      case 'project':
        return <Lock fontSize="small" />;
      case 'global':
        return <Public fontSize="small" />;
      default:
        return null;
    }
  };

  const getConfidenceColor = (conf: number) => {
    if (conf >= 80) return 'success';
    if (conf >= 50) return 'warning';
    return 'error';
  };

  return (
    <>
      <Box display="flex" alignItems="center" gap={1}>
        {/* Quick feedback buttons */}
        {!userFeedback ? (
          <ButtonGroup size="small" variant="outlined">
            <Tooltip title="Mark as true threat">
              <Button
                color="error"
                onClick={() => handleFeedbackClick('true_positive')}
                startIcon={<ThumbUp />}
                disabled={!user}
              >
                True
              </Button>
            </Tooltip>
            <Tooltip title="Mark as false positive">
              <Button
                color="success"
                onClick={() => handleFeedbackClick('false_positive')}
                startIcon={<ThumbDown />}
                disabled={!user}
              >
                False
              </Button>
            </Tooltip>
            <Tooltip title="Not sure">
              <Button
                color="warning"
                onClick={() => handleFeedbackClick('uncertain')}
                startIcon={<QuestionMark />}
                disabled={!user}
              >
                Uncertain
              </Button>
            </Tooltip>
          </ButtonGroup>
        ) : (
          <Chip
            icon={getFeedbackIcon(userFeedback.feedbackType)}
            label={`You marked: ${userFeedback.feedbackType.replace('_', ' ')}`}
            color={userFeedback.feedbackType === 'true_positive' ? 'error' : 
                   userFeedback.feedbackType === 'false_positive' ? 'success' : 'warning'}
            size="small"
          />
        )}

        {/* Stats button */}
        <Tooltip title="View community feedback">
          <IconButton size="small" onClick={handleStatsClick}>
            <Psychology />
          </IconButton>
        </Tooltip>

        {/* Success indicator */}
        {submitted && (
          <Chip
            icon={<CheckCircle />}
            label="Feedback saved"
            color="success"
            size="small"
          />
        )}
      </Box>

      {/* Detailed feedback dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          Provide Feedback on Finding
        </DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 2 }}>
            {/* Feedback type display */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Your Assessment
              </Typography>
              <Chip
                icon={getFeedbackIcon(selectedType || '')}
                label={selectedType?.replace('_', ' ').toUpperCase()}
                color={selectedType === 'true_positive' ? 'error' : 
                       selectedType === 'false_positive' ? 'success' : 'warning'}
              />
            </Box>

            {/* Confidence slider */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Confidence Level: {confidence}%
              </Typography>
              <Slider
                value={confidence}
                onChange={(_, value) => setConfidence(value as number)}
                min={0}
                max={100}
                step={10}
                marks
                color={getConfidenceColor(confidence) as any}
              />
              <Typography variant="caption" color="text.secondary">
                How confident are you in this assessment?
              </Typography>
            </Box>

            {/* Reason text field */}
            <TextField
              label="Reason (Optional)"
              multiline
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Explain why you think this is a true/false positive..."
              helperText="Your explanation helps improve detection accuracy"
            />

            {/* Suppression scope (for false positives) */}
            {selectedType === 'false_positive' && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Suppression Scope
                </Typography>
                <ButtonGroup fullWidth>
                  <Button
                    variant={suppressionScope === 'personal' ? 'contained' : 'outlined'}
                    onClick={() => setSuppressionScope('personal')}
                    startIcon={<Person />}
                  >
                    Personal
                  </Button>
                  <Button
                    variant={suppressionScope === 'team' ? 'contained' : 'outlined'}
                    onClick={() => setSuppressionScope('team')}
                    startIcon={<Group />}
                    disabled={!teamId}
                  >
                    Team
                  </Button>
                  <Button
                    variant={suppressionScope === 'project' ? 'contained' : 'outlined'}
                    onClick={() => setSuppressionScope('project')}
                    startIcon={<Lock />}
                  >
                    Project
                  </Button>
                </ButtonGroup>
                <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
                  Choose who should see this suppression rule
                </Typography>
              </Box>
            )}

            {/* Team sharing toggle */}
            {teamId && (
              <FormControlLabel
                control={
                  <Switch
                    checked={shareWithTeam}
                    onChange={(e) => setShareWithTeam(e.target.checked)}
                  />
                }
                label="Share feedback with team for collective learning"
              />
            )}

            {/* Learning impact info */}
            <Alert severity="info" icon={<Psychology />}>
              Your feedback helps Sigil learn and improve detection accuracy.
              {selectedType === 'false_positive' && 
                ' Similar patterns will be suppressed or confidence-adjusted based on your input.'
              }
              {selectedType === 'true_positive' && 
                ' This confirms the detection was correct and helps prioritize similar issues.'
              }
            </Alert>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)} disabled={loading}>
            Cancel
          </Button>
          <Button
            onClick={handleDialogSubmit}
            variant="contained"
            disabled={loading || !selectedType}
            startIcon={loading ? <CircularProgress size={20} /> : <Shield />}
          >
            Submit Feedback
          </Button>
        </DialogActions>
      </Dialog>

      {/* Stats menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <Box sx={{ p: 2, minWidth: 250 }}>
          <Typography variant="subtitle2" gutterBottom>
            Community Feedback
          </Typography>
          {feedbackStats ? (
            <Stack spacing={1}>
              <Box display="flex" justifyContent="space-between">
                <Chip
                  icon={<ThumbUp />}
                  label={`${feedbackStats.truePositives} True`}
                  size="small"
                  color="error"
                  variant="outlined"
                />
                <Chip
                  icon={<ThumbDown />}
                  label={`${feedbackStats.falsePositives} False`}
                  size="small"
                  color="success"
                  variant="outlined"
                />
              </Box>
              {feedbackStats.uncertain > 0 && (
                <Chip
                  icon={<QuestionMark />}
                  label={`${feedbackStats.uncertain} Uncertain`}
                  size="small"
                  color="warning"
                  variant="outlined"
                />
              )}
              {feedbackStats.consensus !== undefined && (
                <Box display="flex" alignItems="center" gap={1}>
                  <Typography variant="caption">
                    Consensus:
                  </Typography>
                  <Chip
                    label={`${Math.round(feedbackStats.consensus * 100)}%`}
                    size="small"
                    color={feedbackStats.consensus > 0.7 ? 'success' : 'warning'}
                  />
                </Box>
              )}
            </Stack>
          ) : (
            <CircularProgress size={20} />
          )}
        </Box>
      </Menu>
    </>
  );
};