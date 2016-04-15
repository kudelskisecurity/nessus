FROM tharvik/overlay:latest

RUN echo 'dev-python/nessus test' >> /etc/portage/package.env
RUN emerge-accept -o dev-python/nessus

COPY .. /nessus
