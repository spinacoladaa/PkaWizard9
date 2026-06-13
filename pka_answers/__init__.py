"""pka_answers - modulaire tool: vind een .pka, haal de answer-configs eruit, schrijf een
gesorteerd <pka>.answers.txt in dezelfde map.

Modules:
  discover   - .pka-bestanden vinden
  xml_source - de ontsleutelde activity-XML bemachtigen (runtime-dump backend, met cache)
  parse      - XML -> answer-netwerk -> per-device config (IOS-CLI + eind-device IP)
  render     - per-device gesorteerde tekst -> <pka>.answers.txt
"""
