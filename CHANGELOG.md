# Changelog

## [0.4.1](https://github.com/gustav0thethird/Aegis/compare/v0.4.0...v0.4.1) (2026-09-23)


### Fixes

* **auth:** sessions carry identity, not authorisation ([#96](https://github.com/gustav0thethird/Aegis/issues/96)) ([4f8d41b](https://github.com/gustav0thethird/Aegis/commit/4f8d41ba2519383640c74038be021caf61fb01a6))
* **ci:** keep the generated chart README free of version numbers ([#97](https://github.com/gustav0thethird/Aegis/issues/97)) ([ba65d7b](https://github.com/gustav0thethird/Aegis/commit/ba65d7b1f752dffd55d256e5c8018c9451578525))
* **keys:** one implementation for issuing a team-registry key ([#99](https://github.com/gustav0thethird/Aegis/issues/99)) ([4786ef2](https://github.com/gustav0thethird/Aegis/commit/4786ef2f28b05b76b1addf916f715b172cb7baea))
* **settings:** keep third-party credentials out of the API and the change log ([#100](https://github.com/gustav0thethird/Aegis/issues/100)) ([eae70a8](https://github.com/gustav0thethird/Aegis/commit/eae70a87a4049d04d27060582a750af9a0d5419e))

## [0.4.0](https://github.com/gustav0thethird/Aegis/compare/v0.3.0...v0.4.0) (2026-09-23)


### Features

* **auth:** workload identity — authenticate with an OIDC token instead of an API key ([#91](https://github.com/gustav0thethird/Aegis/issues/91)) ([65a0937](https://github.com/gustav0thethird/Aegis/commit/65a09374ea70ee0761af0775e13781f3673dd017))


### Fixes

* **ci:** use the generic updater for the version files ([#94](https://github.com/gustav0thethird/Aegis/issues/94)) ([b734dbf](https://github.com/gustav0thethird/Aegis/commit/b734dbf78a329b1a071c3b2f8059a035e638137b))
* **policy:** one resolution for every policy field, most restrictive wins ([#88](https://github.com/gustav0thethird/Aegis/issues/88)) ([dab6f51](https://github.com/gustav0thethird/Aegis/commit/dab6f51e820818dd9bcd05782529aa4e12193526))
* **release:** docker login in the Chart job so cosign can push the signature; re-runnable by tag ([#83](https://github.com/gustav0thethird/Aegis/issues/83)) ([02d3813](https://github.com/gustav0thethird/Aegis/commit/02d3813ecc3a1bea0888ea2fa56fe1b170f5420e))
* **security:** login brute-force protection, session listing, dedupe key, rate-limit bucket ([#87](https://github.com/gustav0thethird/Aegis/issues/87)) ([e860edf](https://github.com/gustav0thethird/Aegis/commit/e860edf354cdca91cba8e777f65d1d9f3d906fe2))
* **security:** narrow two defaults that decided how far one compromise reaches ([#90](https://github.com/gustav0thethird/Aegis/issues/90)) ([b7e4d1c](https://github.com/gustav0thethird/Aegis/commit/b7e4d1c92240b6725215d404a374adfa7733bdae))
* **security:** stop secrets escaping through error paths and webhook_log ([#86](https://github.com/gustav0thethird/Aegis/issues/86)) ([a2230d9](https://github.com/gustav0thethird/Aegis/commit/a2230d9a71bffd9112a7a4a3bf4d4c8d1e921b46))
* **webhook:** deliver events off the request path ([#89](https://github.com/gustav0thethird/Aegis/issues/89)) ([dd896e5](https://github.com/gustav0thethird/Aegis/commit/dd896e57b12d40ff02b49872d05ba28d373d2609))


### Documentation

* README said keys are token_urlsafe(40)/320-bit; they are (32)/256-bit. ([e860edf](https://github.com/gustav0thethird/Aegis/commit/e860edf354cdca91cba8e777f65d1d9f3d906fe2))
* regenerate MkDocs + catalog [skip ci] ([267d154](https://github.com/gustav0thethird/Aegis/commit/267d1549635e2b76d689a9513f94fe9c849b8e29))
* regenerate MkDocs + catalog [skip ci] ([92a7cc0](https://github.com/gustav0thethird/Aegis/commit/92a7cc0dcec3390f54f294b5568beca3efcd10fe))


### Build and CI

* automate releases end to end with release-please ([#92](https://github.com/gustav0thethird/Aegis/issues/92)) ([25f9088](https://github.com/gustav0thethird/Aegis/commit/25f9088ed618c3bbabf41fbf22175ec078443988))
