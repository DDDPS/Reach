/**
 * The Containers workspace's backend: Docker, Podman and Compose on a saved
 * host (through its SSH session) or a terminal tab's server. See
 * src-tauri/src/ipc/container_commands.rs.
 */

import { invoke, Channel } from '@tauri-apps/api/core';

export type Engine = 'docker' | 'podman';
export type Environment = 'none' | 'development' | 'staging' | 'production';

/** Where a target is reached: this computer, a saved session, or a tab. */
export type Route =
	| { kind: 'direct' }
	| { kind: 'session'; sessionId: string }
	| { kind: 'live'; connectionId: string };

export interface ContainerHost {
	id: string;
	name: string;
	route: Route;
	engine: Engine;
	environment: Environment;
	readOnly: boolean;
	lastUsedAt: number;
}

export interface HostInfo {
	engine: Engine;
	version: string;
	apiVersion: string;
	os: string;
	arch: string;
	compose: boolean;
}

export interface Opened {
	key: string;
	info: HostInfo;
	readOnly: boolean;
}

export interface ContainerRow {
	id: string;
	name: string;
	image: string;
	state: string;
	status: string;
	created: number;
	ports: string[];
	project: string | null;
	service: string | null;
}

export interface ImageRow {
	id: string;
	tags: string[];
	size: number;
	created: number;
	containers: number;
}

export interface VolumeRow {
	name: string;
	driver: string;
	mountpoint: string;
	created: string;
}

export interface NetworkRow {
	id: string;
	name: string;
	driver: string;
	scope: string;
}

export interface Project {
	name: string;
	workingDir: string | null;
	configFiles: string[];
	services: string[];
	running: number;
	total: number;
}

export type ContainerAction = 'start' | 'stop' | 'restart' | 'pause' | 'unpause' | 'kill' | 'remove';
export type ComposeAction = 'up' | 'down' | 'restart' | 'stop' | 'start' | 'pull';
export type RemovableKind = 'image' | 'volume' | 'network';

export const ctrHosts = () => invoke<ContainerHost[]>('ctr_hosts');
export const ctrHostSave = (host: ContainerHost) => invoke<ContainerHost>('ctr_host_save', { host });
export const ctrHostDelete = (id: string) => invoke<void>('ctr_host_delete', { id });

export const ctrOpen = (hostId: string) => invoke<Opened>('ctr_open', { hostId });
export const ctrOpenLive = (connectionId: string, engine: Engine) => invoke<Opened>('ctr_open_live', { connectionId, engine });
export const ctrClose = (key: string) => invoke<void>('ctr_close', { key });

export const ctrContainers = (key: string) => invoke<ContainerRow[]>('ctr_containers', { key });
export const ctrImages = (key: string) => invoke<ImageRow[]>('ctr_images', { key });
export const ctrVolumes = (key: string) => invoke<VolumeRow[]>('ctr_volumes', { key });
export const ctrNetworks = (key: string) => invoke<NetworkRow[]>('ctr_networks', { key });
export const ctrProjects = (key: string) => invoke<Project[]>('ctr_projects', { key });
export const ctrInspect = (key: string, kind: 'container' | RemovableKind, id: string) => invoke<string>('ctr_inspect', { key, kind, id });

export const ctrAct = (key: string, id: string, action: ContainerAction) => invoke<void>('ctr_act', { key, id, action });
export const ctrRemove = (key: string, kind: RemovableKind, id: string) => invoke<void>('ctr_remove', { key, kind, id });
export const ctrCompose = (key: string, project: string, action: ComposeAction) => invoke<string>('ctr_compose', { key, project, action });

/** Follow a container's log; returns a function that stops it. */
export async function ctrLogs(key: string, id: string, tail: number, onData: (chunk: string) => void): Promise<() => void> {
	const streamId = crypto.randomUUID();
	const channel = new Channel<string>();
	channel.onmessage = onData;
	await invoke('ctr_logs', { key, id, streamId, tail, onData: channel });
	return () => void invoke('ctr_logs_stop', { streamId }).catch(() => {});
}

export const ctrShellCommand = (engine: Engine, id: string) => invoke<string>('ctr_shell_command', { engine, id });
