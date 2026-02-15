package dev.nomark.sigil.ui

import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.table.JBTable
import dev.nomark.sigil.runner.ScanResult
import java.awt.BorderLayout
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.table.DefaultTableModel

class SigilToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = SigilPanel()
        val content = ContentFactory.getInstance().createContent(panel, "Findings", false)
        toolWindow.contentManager.addContent(content)

        // Store reference so actions can update
        panels[project] = panel
    }

    companion object {
        private val panels = mutableMapOf<Project, SigilPanel>()

        fun updateFindings(project: Project, result: ScanResult) {
            panels[project]?.update(result)
        }
    }
}

class SigilPanel : JPanel(BorderLayout()) {
    private val tableModel = DefaultTableModel(
        arrayOf("Severity", "Rule", "File", "Line", "Snippet"), 0
    )
    private val table = JBTable(tableModel)
    private val summaryLabel = JLabel("No scan results yet.")

    init {
        add(summaryLabel, BorderLayout.NORTH)
        add(JBScrollPane(table), BorderLayout.CENTER)
        table.autoResizeMode = JBTable.AUTO_RESIZE_LAST_COLUMN
    }

    fun update(result: ScanResult) {
        summaryLabel.text = "${result.verdict} — score: ${result.score}, " +
            "${result.findings.size} findings, ${result.filesScanned} files, ${result.durationMs}ms"

        tableModel.rowCount = 0
        for (f in result.findings) {
            tableModel.addRow(arrayOf(
                f.severity.uppercase(),
                f.rule,
                f.file,
                f.line?.toString() ?: "",
                f.snippet
            ))
        }
    }
}
