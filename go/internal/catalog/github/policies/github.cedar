// Default classification-aware policy for the GitHub catalog tools.
// Adopt or override. Subject = agent acting under a delegation.

// Read & search: allowed within the subject's classification cap.
permit(
  principal,
  action in [Action::"github_read_file", Action::"github_search_code"],
  resource
) when {
  resource.classification <= principal.classification_cap
};

// Create issue: requires at least Registered trust tier.
permit(
  principal,
  action == Action::"github_create_issue",
  resource
) when {
  principal.trust_tier >= 1 &&
  resource.classification <= principal.classification_cap
};

// Delete branch (destructive): Certified+ trust tier and explicit tier-4 cap.
permit(
  principal,
  action == Action::"github_delete_branch",
  resource
) when {
  principal.trust_tier >= 2 &&
  principal.max_action_tier >= 4 &&
  resource.classification <= principal.classification_cap
};
