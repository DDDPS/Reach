<script lang="ts">
	/**
	 * Shown over the whole app while the vault is held locked (by the user or by
	 * auto-lock). Sessions that are already open keep running underneath; what
	 * this gates is the vault, and with it every saved password and key.
	 */
	import Button from '$lib/components/shared/Button.svelte';
	import Input from '$lib/components/shared/Input.svelte';
	import { hasMasterPassword } from '$lib/ipc/credentials';
	import { biometricStatus, type BiometricStatus } from '$lib/ipc/vault';
	import { t } from '$lib/state/i18n.svelte';
	import { biometricName, resume, unlock, vaultState } from '$lib/state/vault.svelte';

	let usePassword = $state(false);
	let password = $state('');
	let error = $state('');
	let busy = $state(false);
	let passwordAvailable = $state(false);
	let biometric = $state<BiometricStatus | null>(null);
	const biometricOn = $derived(!!biometric?.enabled);
	const method = $derived(biometricName(biometric?.method ?? null));
	// With a master password set, a lock is only undone by it or biometrics,
	// never by one click: the backend refuses that too.
	const showPasswordForm = $derived(usePassword || (passwordAvailable && !biometricOn));

	$effect(() => {
		if (vaultState.held) {
			error = '';
			password = '';
			hasMasterPassword()
				.then((has) => (passwordAvailable = has))
				.catch(() => (passwordAvailable = false));
			biometricStatus()
				.then((status) => (biometric = status))
				.catch(() => (biometric = null));
		}
	});

	async function openWithBiometric(): Promise<void> {
		busy = true;
		error = '';
		try {
			if (!(await resume(true))) error = t('lock.biometric_failed', { method });
		} catch {
			error = t('lock.biometric_failed', { method });
		} finally {
			busy = false;
		}
	}

	async function openWithKeychain(): Promise<void> {
		busy = true;
		error = '';
		try {
			if (!(await resume())) error = t('lock.unlock_failed');
		} catch (err) {
			error = String(err);
		} finally {
			busy = false;
		}
	}

	async function openWithPassword(): Promise<void> {
		if (!password) return;
		busy = true;
		error = '';
		try {
			if (!(await unlock(password))) error = t('lock.wrong_password');
		} catch (err) {
			error = String(err);
		} finally {
			busy = false;
			password = '';
		}
	}
</script>

{#if vaultState.held}
	<div class="lock-screen" role="dialog" aria-modal="true" aria-labelledby="lock-title">
		<div class="card">
			<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
				<path
					d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm-3 8V7a3 3 0 1 1 6 0v3H9Z"
				/>
			</svg>
			<h2 id="lock-title">{t('lock.title')}</h2>
			<p class="subtitle">{t('lock.subtitle')}</p>

			{#if showPasswordForm}
				<form
					onsubmit={(e) => {
						e.preventDefault();
						void openWithPassword();
					}}
				>
					<Input type="password" placeholder={t('lock.password_placeholder')} bind:value={password} />
					<Button type="submit" disabled={busy || !password}>{t('lock.unlock')}</Button>
				</form>
				{#if biometricOn}
					<button class="link" onclick={() => (usePassword = false)}>{t('lock.back')}</button>
				{/if}
			{:else}
				{#if biometricOn}
					<Button onclick={() => void openWithBiometric()} disabled={busy}>
						{t('lock.unlock_biometric', { method })}
					</Button>
				{:else}
					<Button onclick={() => void openWithKeychain()} disabled={busy}>{t('lock.unlock')}</Button>
					<p class="hint">{t('lock.set_password_hint')}</p>
				{/if}
				{#if passwordAvailable && biometricOn}
					<button class="link" onclick={() => (usePassword = true)}>{t('lock.use_password')}</button>
				{/if}
			{/if}

			{#if error}
				<p class="error" role="alert">{error}</p>
			{/if}
		</div>
	</div>
{/if}

<style>
	.lock-screen {
		position: fixed;
		inset: 0;
		z-index: 10000;
		display: flex;
		align-items: center;
		justify-content: center;
		background: color-mix(in srgb, var(--color-bg-primary, #111) 88%, transparent);
		backdrop-filter: blur(14px);
	}

	.card {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		width: min(360px, calc(100vw - 32px));
		padding: 28px 24px;
		border-radius: 12px;
		background: var(--color-bg-secondary, #1b1b1b);
		border: 1px solid var(--color-border, #333);
		text-align: center;
	}

	.icon {
		width: 36px;
		height: 36px;
		fill: var(--color-accent, #4c8bf5);
	}

	h2 {
		margin: 0;
		font-size: 1.15em;
		color: var(--color-text-primary, #eee);
	}

	.subtitle {
		margin: 0 0 6px;
		font-size: 0.9em;
		color: var(--color-text-secondary, #aaa);
	}

	form {
		display: flex;
		flex-direction: column;
		gap: 8px;
		width: 100%;
	}

	.link {
		background: none;
		border: none;
		color: var(--color-accent, #4c8bf5);
		cursor: pointer;
		font-size: 0.85em;
	}

	.hint {
		margin: 0;
		font-size: 0.8em;
		color: var(--color-text-secondary, #aaa);
	}

	.error {
		margin: 0;
		font-size: 0.85em;
		color: var(--color-danger, #e5534b);
	}
</style>
