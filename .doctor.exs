%Doctor.Config{
  # Generated Phoenix glue (views, controllers, components, layouts) is
  # excluded: the docs bar applies to domain code (lib/accela_imageboard/*).
  ignore_modules: [
    ~r/^AccelaImageboardWeb\.CoreComponents/,
    ~r/^AccelaImageboardWeb\.Layouts/,
    ~r/^AccelaImageboardWeb\.AuthOverrides/,
    ~r/^AccelaImageboardWeb\.LiveUserAuth/,
    ~r/^AccelaImageboardWeb\.PageHTML/,
    ~r/^AccelaImageboardWeb\.PageController/,
    ~r/^AccelaImageboardWeb\.ErrorHTML/,
    ~r/^AccelaImageboardWeb\.ErrorJSON/,
    ~r/^AccelaImageboardWeb\.Endpoint/,
    ~r/^AccelaImageboardWeb\.Router/,
    ~r/^AccelaImageboardWeb\.Telemetry/,
    ~r/^AccelaImageboardWeb\.Gettext/,
    ~r/^AccelaImageboardWeb$/,
    ~r/^AccelaImageboard\.DataCase/,
    ~r/^AccelaImageboardWeb\.ConnCase/
  ],
  ignore_paths: [],
  min_module_doc_coverage: 100,
  min_module_spec_coverage: 0,
  min_overall_doc_coverage: 60,
  min_overall_moduledoc_coverage: 90,
  min_overall_spec_coverage: 0,
  exception_moduledoc_required: true,
  raise: false,
  reporter: Doctor.Reporters.Full,
  struct_type_spec_required: true,
  umbrella: false
}
