# Homologation Checklist

Use este checklist antes de publicar ou distribuir um aplicativo gerado pelo TauriShield.

## Manifesto

- [ ] `source.url` usa HTTPS.
- [ ] domínio principal está na allowlist.
- [ ] não existe wildcard global.
- [ ] wildcard subdomain foi justificado.
- [ ] `identifier` segue reverse-DNS.
- [ ] permissões opcionais foram revisadas.

## Segurança

- [ ] `shell` está desabilitado.
- [ ] `filesystem` está desabilitado.
- [ ] câmera, microfone e geolocalização estão desabilitados.
- [ ] downloads estão desabilitados ou justificados.
- [ ] clipboard está desabilitado ou justificado.
- [ ] CSP strict aplicado quando possível.
- [ ] `withGlobalTauri` permanece `false`.

## Build

- [ ] `cargo check` executado.
- [ ] `cargo test` executado.
- [ ] `taurishield audit` sem High/Critical.
- [ ] `taurishield sarif` gerado.
- [ ] `taurishield release-check` gerado.
- [ ] SBOM gerado.
- [ ] Checksums gerados.
- [ ] Artefato assinado, quando aplicável.

## Distribuição

- [ ] Release notes preenchidas.
- [ ] Evidências anexadas.
- [ ] Binário testado em ambiente limpo.
- [ ] Política de atualização definida.
- [ ] Canal de reporte de vulnerabilidade documentado.
