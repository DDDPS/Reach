<script lang="ts">
	import Button from '$lib/components/shared/Button.svelte';
	import Input from '$lib/components/shared/Input.svelte';
	import {
		hasMasterPassword,
		setMasterPassword,
		isLocked as checkIsLocked
	} from '$lib/ipc/credentials';
	import { t } from '$lib/state/i18n.svelte';
	import Dropdown from '$lib/components/shared/Dropdown.svelte';
	import Toggle from '$lib/components/shared/Toggle.svelte';
	import { getSettings, updateSetting } from '$lib/state/settings.svelte';
	import { biometricName, lock as lockVault } from '$lib/state/vault.svelte';
	import { biometricDisable, biometricEnable, biometricStatus, type BiometricStatus } from '$lib/ipc/vault';

	const settings = getSettings();
	const autoLockOptions = $derived([
		{ label: t('security.auto_lock_never'), value: '0' },
		...[1, 5, 15, 30, 60].map((m) => ({ label: t('security.auto_lock_minutes', { count: m }), value: String(m) }))
	]);

	let hasPassword = $state(false);
	let locked = $state(false);
	let loading = $state(true);

	let showPasswordForm = $state(false);
	let newPassword = $state('');
	let confirmPassword = $state('');
	let error = $state('');
	let saving = $state(false);

	let biometric = $state<BiometricStatus | null>(null);
	let biometricBusy = $state(false);
	let biometricError = $state('');
	const method = $derived(biometricName(biometric?.method ?? null));
	const biometricNote = $derived.by(() => {
		if (!biometric?.available) return t('security.biometric_unavailable', { method });
		if (!hasPassword) return t('security.biometric_needs_password', { method });
		return t('security.biometric_desc', { method });
	});

	async function toggleBiometric(on: boolean) {
		biometricBusy = true;
		biometricError = '';
		try {
			if (on) await biometricEnable();
			else await biometricDisable();
		} catch (e) {
			biometricError = String(e);
		}
		try {
			biometric = await biometricStatus();
		} catch {
			// Keep the last known state
		}
		biometricBusy = false;
	}

	$effect(() => {
		loadStatus();
	});

	async function loadStatus() {
		loading = true;
		try {
			hasPassword = await hasMasterPassword();
			locked = await checkIsLocked();
			biometric = await biometricStatus().catch(() => null);
		} catch {
			// IPC not available in dev, set safe defaults
			hasPassword = false;
			locked = false;
		}
		loading = false;
	}

	function openPasswordForm() {
		showPasswordForm = true;
		newPassword = '';
		confirmPassword = '';
		error = '';
	}

	function cancelPasswordForm() {
		showPasswordForm = false;
		newPassword = '';
		confirmPassword = '';
		error = '';
	}

	async function savePassword() {
		error = '';

		if (newPassword.length < 8) {
			error = t('security.password_too_short');
			return;
		}

		if (newPassword !== confirmPassword) {
			error = t('security.passwords_mismatch');
			return;
		}

		saving = true;
		try {
			await setMasterPassword(newPassword);
			hasPassword = true;
			showPasswordForm = false;
			newPassword = '';
			confirmPassword = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to set password';
		}
		saving = false;
	}

	async function handleLock() {
		try {
			// Held: the lock screen shows, and only the user opens it again.
			await lockVault();
			locked = true;
		} catch {
			// Lock failed
		}
	}
</script>

<div class="tab-content">
	<div class="setting-row">
		<div class="setting-info">
			<span class="setting-label">{t('security.master_password_status')}</span>
			<span class="setting-description">
				{#if loading}
					Checking...
				{:else if hasPassword}
					{t('security.password_set')}
				{:else}
					{t('security.no_password')}
				{/if}
			</span>
		</div>
		<div class="setting-control">
			<div class="status-badge" class:set={hasPassword && !loading}>
				{#if loading}
					...
				{:else if hasPassword}
					<svg width="14" height="14" viewBox="0 0 14 14" fill="none">
						<path d="M2 7L5.5 10.5L12 3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
					</svg>
					Set
				{:else}
					<svg width="14" height="14" viewBox="0 0 14 14" fill="none">
						<path d="M1 1L13 13M13 1L1 13" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" />
					</svg>
					Not set
				{/if}
			</div>
		</div>
	</div>

	<div class="setting-row">
		<div class="setting-info">
			<span class="setting-label">{t('security.lock_status')}</span>
			<span class="setting-description">
				{#if locked}
					Credentials are locked and encrypted
				{:else}
					Credentials are currently accessible
				{/if}
			</span>
		</div>
		<div class="setting-control">
			<div class="lock-badge" class:locked>
				{#if locked}
					<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
						<path d="M7 11V7a5 5 0 0 1 10 0v4" />
					</svg>
					{t('security.locked')}
				{:else}
					<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
						<path d="M7 11V7a5 5 0 0 1 9.9-1" />
					</svg>
					{t('security.unlocked')}
				{/if}
			</div>
		</div>
	</div>

	<div class="setting-row">
		<div class="setting-info">
			<span class="setting-label">{t('security.auto_lock')}</span>
			<span class="setting-description">{t('security.auto_lock_desc')}</span>
		</div>
		<div class="setting-control">
			<Dropdown
				options={autoLockOptions}
				selected={String(settings.autoLockMinutes)}
				onchange={(value) => updateSetting('autoLockMinutes', Number(value))}
			/>
		</div>
	</div>

	<div class="setting-row">
		<div class="setting-info">
			<span class="setting-label">{t('security.lock_on_system_lock')}</span>
			<span class="setting-description">{t('security.lock_on_system_lock_desc')}</span>
		</div>
		<div class="setting-control">
			<Toggle
				hideLabel
				checked={settings.lockOnSystemLock}
				label={t('security.lock_on_system_lock')}
				onchange={(checked) => updateSetting('lockOnSystemLock', checked)}
			/>
		</div>
	</div>

	{#if biometric?.method}
		<div class="setting-row">
			<div class="setting-info">
				<span class="setting-label">{t('security.biometric', { method })}</span>
				<span class="setting-description">{biometricNote}</span>
				{#if biometricError}
					<span class="form-error">{biometricError}</span>
				{/if}
			</div>
			<div class="setting-control">
				<Toggle
					hideLabel
					checked={biometric.enabled}
					label={t('security.biometric', { method })}
					disabled={biometricBusy || locked || (!biometric.enabled && (!biometric.available || !hasPassword))}
					onchange={(checked) => void toggleBiometric(checked)}
				/>
			</div>
		</div>
	{/if}

	<div class="action-row">
		{#if !showPasswordForm}
			<Button
				variant="secondary"
				size="sm"
				onclick={openPasswordForm}
			>
				{hasPassword ? t('security.change_password') : t('security.set_password')}
			</Button>

			{#if !locked}
				<Button
					variant="danger"
					size="sm"
					onclick={handleLock}
				>
					{t('security.lock_now')}
				</Button>
			{/if}
		{/if}
	</div>

	{#if showPasswordForm}
		<div class="password-form">
			<div class="form-field">
				<Input
					label={t('security.new_password')}
					type="password"
					placeholder="Enter new password"
					bind:value={newPassword}
				/>
			</div>

			<div class="form-field">
				<Input
					label={t('security.confirm_password')}
					type="password"
					placeholder="Re-enter password"
					bind:value={confirmPassword}
				/>
			</div>

			{#if error}
				<div class="form-error">{error}</div>
			{/if}

			<div class="form-actions">
				<Button
					variant="ghost"
					size="sm"
					onclick={cancelPasswordForm}
				>
					{t('common.cancel')}
				</Button>
				<Button
					variant="primary"
					size="sm"
					disabled={saving || newPassword.length === 0}
					onclick={savePassword}
				>
					{saving ? t('security.saving') : t('security.save_password')}
				</Button>
			</div>
		</div>
	{/if}
</div>

<style>

	.status-badge {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 4px 10px;
		border-radius: 6px;
		font-size: 0.75rem;
		font-weight: 500;
		background-color: rgba(255, 69, 58, 0.12);
		color: var(--color-danger);
	}

	.status-badge.set {
		background-color: rgba(48, 209, 88, 0.12);
		color: var(--color-success);
	}

	.lock-badge {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 4px 10px;
		border-radius: 6px;
		font-size: 0.75rem;
		font-weight: 500;
		background-color: rgba(255, 214, 10, 0.12);
		color: var(--color-warning);
	}

	.lock-badge.locked {
		background-color: rgba(48, 209, 88, 0.12);
		color: var(--color-success);
	}

	.password-form {
		display: flex;
		flex-direction: column;
		gap: 12px;
		padding: 16px;
		margin-top: 8px;
		background-color: var(--color-bg-secondary);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-card);
	}

	.form-field {
		width: 100%;
	}

	.form-error {
		font-size: 0.75rem;
		color: var(--color-danger);
		padding: 4px 0;
	}

	.form-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
		padding-top: 4px;
	}
</style>
