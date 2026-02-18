package dev.nomark.sigil.ui

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.ui.table.JBTable
import dev.nomark.sigil.runner.QuarantineItem
import dev.nomark.sigil.runner.SigilRunner
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.awt.event.ActionEvent
import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableCellEditor
import javax.swing.table.TableCellRenderer

class QuarantinePanel(private val project: Project) : JPanel(BorderLayout()) {

    private val items = mutableListOf<QuarantineItem>()
    private val tableModel = QuarantineTableModel(items)
    private val table = JBTable(tableModel)
    private val emptyLabel = JLabel("No quarantined items.", SwingConstants.CENTER)

    init {
        val topPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        val refreshButton = JButton("Refresh")
        refreshButton.addActionListener { refreshQuarantine() }
        topPanel.add(refreshButton)

        add(topPanel, BorderLayout.NORTH)

        table.setDefaultRenderer(JPanel::class.java, ButtonPanelRenderer())
        table.setDefaultEditor(JPanel::class.java, ButtonPanelEditor(project, this))
        table.rowHeight = 36
        table.autoResizeMode = JBTable.AUTO_RESIZE_ALL_COLUMNS

        val scrollPane = JScrollPane(table)
        add(scrollPane, BorderLayout.CENTER)
        add(emptyLabel, BorderLayout.SOUTH)

        refreshQuarantine()
    }

    fun refreshQuarantine() {
        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Sigil: Loading quarantine list...", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        val runner = SigilRunner(project)
                        val result = runner.listQuarantine()
                        ApplicationManager.getApplication().invokeLater {
                            items.clear()
                            items.addAll(result)
                            tableModel.fireTableDataChanged()
                            emptyLabel.isVisible = items.isEmpty()
                        }
                    } catch (ex: Exception) {
                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("Sigil")
                            .createNotification(
                                "Sigil: Quarantine Error",
                                ex.message ?: "Failed to load quarantine list",
                                NotificationType.ERROR
                            )
                            .notify(project)
                    }
                }
            }
        )
    }
}

private class QuarantineTableModel(private val items: List<QuarantineItem>) : AbstractTableModel() {
    private val columns = arrayOf("Status", "Source", "Type", "Score", "Actions")

    override fun getRowCount(): Int = items.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return if (columnIndex == 4) JPanel::class.java else String::class.java
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean = columnIndex == 4

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val item = items[rowIndex]
        return when (columnIndex) {
            0 -> item.status
            1 -> item.source
            2 -> item.sourceType
            3 -> item.scanScore?.toString() ?: ""
            4 -> item  // Pass the item so renderer/editor can use id
            else -> ""
        }
    }
}

private class ButtonPanelRenderer : TableCellRenderer {
    override fun getTableCellRendererComponent(
        table: JTable, value: Any?, isSelected: Boolean,
        hasFocus: Boolean, row: Int, column: Int
    ): Component {
        val panel = JPanel(FlowLayout(FlowLayout.CENTER, 4, 2))
        panel.add(JButton("Approve"))
        panel.add(JButton("Reject"))
        if (isSelected) {
            panel.background = table.selectionBackground
        } else {
            panel.background = table.background
        }
        return panel
    }
}

private class ButtonPanelEditor(
    private val project: Project,
    private val quarantinePanel: QuarantinePanel
) : AbstractCellEditor(), TableCellEditor {

    private val panel = JPanel(FlowLayout(FlowLayout.CENTER, 4, 2))
    private val approveButton = JButton("Approve")
    private val rejectButton = JButton("Reject")
    private var currentItem: QuarantineItem? = null

    init {
        panel.add(approveButton)
        panel.add(rejectButton)

        approveButton.addActionListener { _: ActionEvent ->
            stopCellEditing()
            val item = currentItem ?: return@addActionListener
            ProgressManager.getInstance().run(
                object : Task.Backgroundable(project, "Sigil: Approving ${item.id}...", false) {
                    override fun run(indicator: ProgressIndicator) {
                        try {
                            val runner = SigilRunner(project)
                            val ok = runner.approveItem(item.id)
                            ApplicationManager.getApplication().invokeLater {
                                if (ok) {
                                    quarantinePanel.refreshQuarantine()
                                } else {
                                    NotificationGroupManager.getInstance()
                                        .getNotificationGroup("Sigil")
                                        .createNotification(
                                            "Sigil: Approve Failed",
                                            "Could not approve item ${item.id}",
                                            NotificationType.ERROR
                                        )
                                        .notify(project)
                                }
                            }
                        } catch (ex: Exception) {
                            NotificationGroupManager.getInstance()
                                .getNotificationGroup("Sigil")
                                .createNotification(
                                    "Sigil: Approve Error",
                                    ex.message ?: "Unknown error",
                                    NotificationType.ERROR
                                )
                                .notify(project)
                        }
                    }
                }
            )
        }

        rejectButton.addActionListener { _: ActionEvent ->
            stopCellEditing()
            val item = currentItem ?: return@addActionListener
            ProgressManager.getInstance().run(
                object : Task.Backgroundable(project, "Sigil: Rejecting ${item.id}...", false) {
                    override fun run(indicator: ProgressIndicator) {
                        try {
                            val runner = SigilRunner(project)
                            val ok = runner.rejectItem(item.id)
                            ApplicationManager.getApplication().invokeLater {
                                if (ok) {
                                    quarantinePanel.refreshQuarantine()
                                } else {
                                    NotificationGroupManager.getInstance()
                                        .getNotificationGroup("Sigil")
                                        .createNotification(
                                            "Sigil: Reject Failed",
                                            "Could not reject item ${item.id}",
                                            NotificationType.ERROR
                                        )
                                        .notify(project)
                                }
                            }
                        } catch (ex: Exception) {
                            NotificationGroupManager.getInstance()
                                .getNotificationGroup("Sigil")
                                .createNotification(
                                    "Sigil: Reject Error",
                                    ex.message ?: "Unknown error",
                                    NotificationType.ERROR
                                )
                                .notify(project)
                        }
                    }
                }
            )
        }
    }

    override fun getTableCellEditorComponent(
        table: JTable, value: Any?, isSelected: Boolean, row: Int, column: Int
    ): Component {
        currentItem = value as? QuarantineItem
        return panel
    }

    override fun getCellEditorValue(): Any = currentItem ?: ""
}
