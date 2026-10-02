Containers and Kubernetes, through your SSH sessions.

- New: Containers. Docker and Podman on your servers, through the SSH
  sessions you already have: Compose stacks, live logs, a shell inside a
  container, images, volumes and networks.
- New: Kubernetes. Clusters from a kubeconfig, directly or through SSH:
  what needs attention in plain words, workloads, logs, events, YAML, and
  Helm releases with history and rollback.
- Linux: `apt install reach` and `dnf install reach` from Reach's signed
  repositories, so system updates keep it current. See the download page.
- Mark a host or cluster as Production: it starts read-only, changes ask
  first, and deleting asks for the name.
- Both are switched on in Settings → DevOps.
- Fixed: a connect with a one-off login shell could have saved that shell
  into the session.

Full details: https://github.com/alexandrosnt/Reach/blob/main/CHANGELOG.md
