package dev.nomark.sigil.settings

import com.intellij.openapi.options.BoundConfigurable
import com.intellij.openapi.project.Project
import com.intellij.ui.dsl.builder.*

class SigilConfigurable(private val project: Project) :
    BoundConfigurable("Sigil") {

    private val settings = SigilSettings.getInstance(project)

    override fun createPanel() = panel {
        group("General") {
            row("Sigil binary path:") {
                textField()
                    .bindText(settings::binaryPath)
                    .columns(COLUMNS_LARGE)
                    .comment("Path to the sigil CLI. Use 'sigil' if it's on your PATH.")
            }
            row {
                checkBox("Auto-scan on save")
                    .bindSelected(settings::autoScanOnSave)
            }
        }

        group("Scan Options") {
            row("Minimum severity:") {
                comboBox(listOf("low", "medium", "high", "critical"))
                    .bindItem(settings::severityThreshold.toNullableProperty())
            }
            row("Phases:") {
                textField()
                    .bindText(settings::phases)
                    .columns(COLUMNS_LARGE)
                    .comment("Comma-separated phases. Leave blank for all.")
            }
        }

        group("Cloud API") {
            row("API endpoint:") {
                textField()
                    .bindText(settings::apiEndpoint)
                    .columns(COLUMNS_LARGE)
                    .comment("Leave blank for default (api.sigilsec.ai)")
            }
        }
    }
}
