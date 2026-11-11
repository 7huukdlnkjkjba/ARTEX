package db

import "time"

// Built-in free model pool (FREE POOL).
//
// A pool "account" is one free source profile, e.g. the keyless Pollinations
// endpoint or an OpenRouter free-tier key. The account row only links the source
// to its llm_profiles row; the credentials and model live on the profile so the
// existing activation / failover / usage plumbing keeps working unchanged.

// FreePoolAccount is one pool member with its profile denormalized for listing.
type FreePoolAccount struct {
	ID          int64     `json:"id"`
	Source      string    `json:"source"`
	Label       string    `json:"label"`
	ProfileID   int64     `json:"profile_id"`
	ProfileName string    `json:"profile_name"`
	Model       string    `json:"model"`
	BaseURL     string    `json:"base_url"`
	APIKeyHint  string    `json:"api_key_hint,omitempty"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListFreePoolAccounts returns pool members joined with their profile.
func (d *DB) ListFreePoolAccounts() ([]FreePoolAccount, error) {
	rows, err := d.Query(`
SELECT a.id, a.source, a.label, a.profile_id, p.name, p.model,
       COALESCE(p.base_url, ''), COALESCE(p.api_key_hint, ''), p.is_default, a.created_at
FROM free_pool_accounts a
JOIN llm_profiles p ON p.id = a.profile_id
ORDER BY a.source, a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FreePoolAccount
	for rows.Next() {
		var a FreePoolAccount
		if err := rows.Scan(&a.ID, &a.Source, &a.Label, &a.ProfileID, &a.ProfileName, &a.Model,
			&a.BaseURL, &a.APIKeyHint, &a.IsDefault, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddFreePoolAccount links an existing profile to a free source.
func (d *DB) AddFreePoolAccount(source, label string, profileID int64) (int64, error) {
	var id int64
	err := d.QueryRow(`INSERT INTO free_pool_accounts(source, label, profile_id)
VALUES ($1, $2, $3)
ON CONFLICT (profile_id) DO UPDATE SET source = EXCLUDED.source, label = EXCLUDED.label
RETURNING id`, source, label, profileID).Scan(&id)
	return id, err
}

// DeleteFreePoolAccount removes the account link (the profile itself is deleted
// by the caller so an operator can unwind a pool member completely).
func (d *DB) DeleteFreePoolAccount(id int64) (profileID int64, err error) {
	err = d.QueryRow(`DELETE FROM free_pool_accounts WHERE id=$1 RETURNING profile_id`, id).Scan(&profileID)
	return profileID, err
}

// FreePoolUsageToday counts today's LLM calls for a profile name and how many of
// them failed — the "quota" signal the pool UI shows per account.
func (d *DB) FreePoolUsageToday(profileName string) (calls, failed int, err error) {
	err = d.QueryRow(`
SELECT COUNT(*), COUNT(*) FILTER (WHERE COALESCE(status, '') <> '' AND status <> 'ok')
FROM llm_usage
WHERE profile_name = $1 AND ts >= date_trunc('day', now())`, profileName).Scan(&calls, &failed)
	return calls, failed, err
}
