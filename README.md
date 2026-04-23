# GHCR Container Image Template

A template repository for automatically building and pushing container (Docker) images to [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

To use this repository click `Use this template` and modify [`Dockerfile`](Dockerfile).

[GitHub actions](.github/workflows/build.yml) will build every image for AMD64 and ARM64.
- Every push to `main` is pushed to `ghcr.io/${{ github.repository }}:main`.
- Tags are pushed to `ghcr.io/${{ github.repository }}:TAG`.
