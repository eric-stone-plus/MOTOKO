---
name: geo-estimate
description: Estimate where a photo was taken as an investigative lead — a repeatable manual workflow plus an optional, offline local-inference wrapper. Use for authorized image review; never as evidence, never to identify a person, and never by uploading the image to a third-party service.
---

# Image geolocation estimates

An estimate is a LEAD for manual verification. It is not a fact about where a
photo was taken, it is not evidence, and it never identifies a person. The
default path is the manual workflow below — zero dependencies, no network. The
optional local-inference path adds one machine estimate to the same workflow;
it never replaces the manual corroboration, and nothing here enters the asset
graph (the engine has no image entity domain — this is deliberately not a rule
or a verifier).

## Precision expectation (read before the first estimate)

On OSV-5M — 5.1M street-view images with strict train/test separation, the
current honest benchmark — the best open method (StreetCLIP + kNN retrieval)
reaches **city level 19.9% with a mean error of 1386 km**; the paper's best
trained model: city 5.9%, mean error 1814 km. Read that as: roughly one image
in five gets the right city; the other four do not even reach the right city.
Vendor "meter-level" claims measure something else (a human preselects the
region; the imagery carries context) and must never be mixed with these
numbers. State the benchmark whenever you state a percentage.

## The manual workflow (the default; no dependencies)

Treat the image as the only input and every observation as a lead. Work in
this order, and record each observation with where it came from:

1. Preserve first. Copy the original (never re-encode), record its sha256, and
   work on the copy. Stripping metadata is destroying evidence.
2. Metadata pass. EXIF/GPS, camera make and model, timestamps, software
   fields. A GPS tag is a claim to verify, not an answer — it can be wrong,
   stale, or inherited from a different photo.
3. Text and language. Signage, shop and street names, language and script,
   transliteration, units, phone-number formats, alphabets.
4. Vehicles and plates. Plate format and color, driving side, vehicle models
   and trims, bus/taxi livery, road markings and signs (country-specific).
5. Vegetation and terrain. Species and canopy shape, season, soil color, rock
   and landform, water bodies, snow line, agricultural patterns.
6. Shadows and sun angle. Shadow direction and length, sun elevation;
   cross-check candidate places and times with a solar calculator (the file's
   own timestamp is a hypothesis). This is the strongest and the most
   error-prone signal — verify it against several candidates.
7. Architecture and built environment. Roof shapes, window frames, wall
   materials, brickwork, balconies, fences, street furniture.
8. Utility markings. Pole designs, wire patterns, transformer tags, meter
   boxes, painted service marks — operator-specific and highly localizing.
9. Reflections and incidental detail. Windows, mirrors, glasses, screens, the
   photographer's own shadow — often the only view of what is off-frame.
10. Assemble and verify. Rank candidate locations, then try to FALSIFY the top
    candidate with independent checks (map and imagery cross-reference,
    street-level coverage). Report the candidate, the supporting observations,
    and the contradicting ones.

Reverse image search is an operator decision, not a default: it uploads the
image to a third party (Yandex > Bing > Google is Bellingcat's tested ordering,
and each engine has a geographic bias; Yandex carries the geopolitical
caveat). Decide with the operator before uploading anything sensitive. The
manual workflow above and the local model below never upload the image.

## Optional local inference (GeoCLIP)

The optional path adds one local machine estimate. It is an OPTIONAL external
installation — never an engine dependency:

- GeoCLIP is MIT-licensed (weights 43,769,772 B, shipped inside the pip
  package); it is the only fully licensed local option in the survey.
- The runtime stack is large: the torch manylinux wheel alone measures
  554.6 MB and declares four hard nvidia-* dependencies, so the full install
  is roughly 0.6–3 GB. Nothing in `engine/` may import torch or geoclip, no
  test may import the runner, and no weights are vendored into this tree.
- `geoest.py` (in the engine checkout) is the stdlib-only wrapper; it checks
  the whole installation BEFORE anything runs and refuses (exit 2, remedy
  naming `MOTOKO_GEOEST_VENV`) when a piece is missing. `geoest_runner.py`
  is the one file that imports torch/geoclip, executed only with the venv's
  own python. A public checkout ships this method, not the wrapper.

### Install (operator, once, with network)

The venv is named by `MOTOKO_GEOEST_VENV` — no default. The conventional
location is `$MOTOKO_TOOLS/.geoest-runtime/venv`, with a `weights/` directory
beside the venv:

```bash
ROOT="${MOTOKO_TOOLS:-$PWD/tools}/.geoest-runtime"
python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install geoclip==1.2.3

# Copy the pinned weights out of the package so the wrapper can verify them
# independently of the venv, then record digests (optional, recommended).
mkdir -p "$ROOT/weights"
cp "$ROOT"/venv/lib/python*/site-packages/geoclip/model/weights/*.pth "$ROOT/weights/"
cp "$ROOT"/venv/lib/python*/site-packages/geoclip/model/gps_gallery/coordinates_100K.csv "$ROOT/weights/"
(cd "$ROOT/weights" && sha256sum *.pth coordinates_100K.csv > SHA256SUMS)

# One-time: pre-cache the CLIP ViT-L/14 backbone (~1.7 GB; model.safetensors
# alone is 1,710,540,580 B) so inference never needs the network again.
"$ROOT/venv/bin/python" -c "from transformers import CLIPModel; CLIPModel.from_pretrained('openai/clip-vit-large-patch14')"

export MOTOKO_GEOEST_VENV="$ROOT/venv"
```

### Check and run

```bash
python3 geoest.py --check            # readiness, no image
python3 geoest.py --image /path/photo.jpg
python3 geoest.py --image /path/photo.jpg --json
```

`--check` reports every piece by name (venv, runner, weights, digests). A run
prints the validated estimate; `--json` prints the schema object for a
recording script.

### First-run acceptance (operator, once per installation)

1. Run one sample image and confirm the output carries the boundary field:
   `python3 geoest.py --image sample.jpg --json`.
2. Prove the image does not leave the machine: repeat the same run under a
   packet capture (e.g. `tcpdump -i any -w geoest-run.pcap` around the run)
   and confirm zero outbound traffic from the runner, or run it under
   `unshare -n` and confirm the same estimate. Record the evidence.
3. Record the CPU latency of the run (`time python3 geoest.py
   --image sample.jpg`) — the plan requires a measured number, and none is
   measured yet.

## Output schema and field boundaries

| field | meaning | may be used for | may NOT be used for |
|---|---|---|---|
| `estimate` | top-1 gallery candidate as `latitude`/`longitude` | ranking manual candidate locations; seeding map checks | asserting where the photo was taken; entering evidence or the asset graph |
| `confidence` | the model's own top-1 ranking score in [0, 1] | ordering candidates within one run | reading as P(correct) — it is not calibrated |
| `leads_not_evidence` | the boundary assertion (always `true`; the wrapper refuses output without it) | enforcing that the output is a lead | ignoring it: a missing or false value is a refusal, never a warning |
| `model` | `name` + `version` of the producing model | provenance and reproducibility of a run | citing the model as an authority |

## Hard guarantees

- The image never leaves the machine: the wrapper imports no network module
  (the suite asserts this over the source and its AST), and the runner loads
  every tensor from local paths.
- No network at inference time: the wrapper forces `HF_HUB_OFFLINE=1` and
  `TRANSFORMERS_OFFLINE=1` for the runner, so a missing cache entry fails
  instead of dialing out. Downloads happen only in the operator's one-time
  setup, never in a run.
- Weights are verified by size — 43,769,772 B across the four pinned files —
  and by sha256 when a `SHA256SUMS` file is recorded. The wrapper never
  downloads weights on demand, and a missing or truncated file is a refusal
  before any interpreter starts.

## Limits and refusals

Exit 0 means a validated estimate was printed; exit 2 means a refusal — a
missing piece, an unreadable runner result, or a schema violation. Nothing is
printed on a refusal: there is no partial estimate and no best guess. The
wrapper refuses an unset or missing venv, a missing runner, a missing or
undersized weights file, a digest mismatch, and any runner result that omits
the boundary field or carries an out-of-range value.

It will not identify people, match faces, upload the image anywhere, assert a
location as fact, or produce street/address-level answers — city-level is the
honest ceiling. For images of people or private places, remember that a
candidate location is personal data about someone: follow the engagement's
authorization and the operator's policy before recording candidates.
