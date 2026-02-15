package dev.nomark.sigil.settings

import com.intellij.openapi.components.*
import com.intellij.openapi.project.Project

@Service(Service.Level.PROJECT)
@State(
    name = "SigilSettings",
    storages = [Storage("sigil.xml")]
)
class SigilSettings : PersistentStateComponent<SigilSettings.State> {
    data class State(
        var binaryPath: String = "sigil",
        var autoScanOnSave: Boolean = false,
        var severityThreshold: String = "low",
        var phases: String = "",
        var apiEndpoint: String = ""
    )

    private var state = State()

    var binaryPath: String
        get() = state.binaryPath
        set(value) { state.binaryPath = value }

    var autoScanOnSave: Boolean
        get() = state.autoScanOnSave
        set(value) { state.autoScanOnSave = value }

    var severityThreshold: String
        get() = state.severityThreshold
        set(value) { state.severityThreshold = value }

    var phases: String
        get() = state.phases
        set(value) { state.phases = value }

    var apiEndpoint: String
        get() = state.apiEndpoint
        set(value) { state.apiEndpoint = value }

    override fun getState(): State = state
    override fun loadState(state: State) { this.state = state }

    companion object {
        fun getInstance(project: Project): SigilSettings =
            project.getService(SigilSettings::class.java)
    }
}
