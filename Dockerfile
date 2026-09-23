# Supply a reviewed Linux Python image, preferably by immutable digest.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="Agent Effect Gate" \
      org.opencontainers.image.description="Task-scoped tools, approvals and recoverable execution"
WORKDIR /opt/aeg-source
COPY dist/agent-effect-gate.pyz dist/agent-effect-gate.pyz
COPY dist/SHA256SUMS dist/SHA256SUMS
COPY install.py install.py
RUN python install.py --prefix /opt/aeg \
    && groupadd --system aeg \
    && useradd --system --gid aeg --home-dir /var/lib/aeg --create-home aeg
ENV PATH="/opt/aeg/bin:${PATH}"
USER aeg
WORKDIR /var/lib/aeg
ENTRYPOINT ["agent-effect-gate"]
CMD ["--help"]
# This template does not install optional dependencies or qualify code isolation.
# Mount/provision protected state, rootfs and anchors using a reviewed host policy.
