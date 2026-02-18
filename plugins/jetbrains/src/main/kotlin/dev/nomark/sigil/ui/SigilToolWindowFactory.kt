package dev.nomark.sigil.ui

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTabbedPane
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.treeStructure.Tree
import dev.nomark.sigil.runner.ScanFinding
import dev.nomark.sigil.runner.ScanResult
import java.awt.BorderLayout
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreePath

class SigilToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val mainPanel = SigilPanel(project)
        val content = ContentFactory.getInstance().createContent(mainPanel, "", false)
        toolWindow.contentManager.addContent(content)

        panels[project] = mainPanel
    }

    companion object {
        private val panels = mutableMapOf<Project, SigilPanel>()

        fun updateFindings(project: Project, result: ScanResult) {
            ApplicationManager.getApplication().invokeLater {
                panels[project]?.updateFindings(result)
            }
        }
    }
}

class SigilPanel(project: Project) : JPanel(BorderLayout()) {

    private val summaryLabel = JLabel("No scan results yet.")
    private val rootNode = DefaultMutableTreeNode("Findings")
    private val treeModel = DefaultTreeModel(rootNode)
    private val tree = Tree(treeModel)

    init {
        tree.isRootVisible = false
        tree.showsRootHandles = true

        tree.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) {
                    val path = tree.getPathForLocation(e.x, e.y) ?: return
                    val node = path.lastPathComponent as? DefaultMutableTreeNode ?: return
                    val userObj = node.userObject
                    if (userObj is FindingNode) {
                        val finding = userObj.finding
                        val line = finding.line ?: return
                        if (finding.file.isBlank()) return
                        val vf = LocalFileSystem.getInstance().findFileByPath(finding.file) ?: return
                        OpenFileDescriptor(project, vf, line - 1, 0).navigate(true)
                    }
                }
            }
        })

        val tabbedPane = JBTabbedPane()

        val findingsPanel = JPanel(BorderLayout())
        findingsPanel.add(summaryLabel, BorderLayout.NORTH)
        findingsPanel.add(JBScrollPane(tree), BorderLayout.CENTER)

        val quarantinePanel = QuarantinePanel(project)

        tabbedPane.addTab("Findings", findingsPanel)
        tabbedPane.addTab("Quarantine", quarantinePanel)

        add(tabbedPane, BorderLayout.CENTER)
    }

    fun updateFindings(result: ScanResult) {
        summaryLabel.text = "${result.verdict} — score: ${result.score}, " +
            "${result.findings.size} findings, ${result.filesScanned} files, ${result.durationMs}ms"

        rootNode.removeAllChildren()

        val severityOrder = listOf("critical", "high", "medium", "low")
        val grouped = result.findings.groupBy { it.severity.lowercase() }

        for (severity in severityOrder) {
            val group = grouped[severity] ?: continue
            if (group.isEmpty()) continue

            val severityLabel = severity.replaceFirstChar { it.uppercaseChar() }
            val severityNode = DefaultMutableTreeNode(severityLabel)

            for (finding in group) {
                val label = buildString {
                    append("[${finding.rule}]")
                    if (finding.file.isNotBlank()) {
                        val fileName = finding.file.substringAfterLast('/')
                        append(" $fileName")
                        finding.line?.let { append(":$it") }
                    }
                }
                val leafNode = DefaultMutableTreeNode(FindingNode(finding, label))
                severityNode.add(leafNode)
            }

            rootNode.add(severityNode)
        }

        // Handle any severities not in the standard list
        val extraSeverities = grouped.keys - severityOrder.toSet()
        for (severity in extraSeverities) {
            val group = grouped[severity] ?: continue
            val severityLabel = severity.replaceFirstChar { it.uppercaseChar() }
            val severityNode = DefaultMutableTreeNode(severityLabel)
            for (finding in group) {
                val label = buildString {
                    append("[${finding.rule}]")
                    if (finding.file.isNotBlank()) {
                        val fileName = finding.file.substringAfterLast('/')
                        append(" $fileName")
                        finding.line?.let { append(":$it") }
                    }
                }
                severityNode.add(DefaultMutableTreeNode(FindingNode(finding, label)))
            }
            rootNode.add(severityNode)
        }

        treeModel.reload()

        // Expand all severity nodes
        for (i in 0 until rootNode.childCount) {
            val child = rootNode.getChildAt(i) as? DefaultMutableTreeNode ?: continue
            val nodePath = TreePath(treeModel.getPathToRoot(child))
            tree.expandPath(nodePath)
        }
    }
}

private data class FindingNode(val finding: ScanFinding, private val label: String) {
    override fun toString(): String = label
}
