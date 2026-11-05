# swarma-services

Small swarma services that run on the operator's machine. Each service is its own subproject with its own Go module,
README and skill. One repository holds them for now, because it is not yet known which of them stay needed once the
keyholder exists. A subproject must stay movable: no shared internals between subprojects, and connections to other
swarma modules (keyvault, pulse, Curator) only through plugin or configuration seams.

Owner decision, 2026-11-01: «давай сделаем проект свармма-службы или чо ттакое и там будет подпроектик сварма сайнер /
т.е в гите эт будет в одном проеке, почему так, потому что я пока не знаю нужны ли они будут уже поле того как поялвится
ключник».

## Subprojects

- [signer](signer/README.md): release signer. Builds a reviewed commit of an allowlisted tool and signs the result.

- [shell-out](shell-out/README.md): manual private shell output capture, bounded previews and stable references.
