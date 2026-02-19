package dev.nomark.sigil.actions

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import dev.nomark.sigil.runner.SigilRunner
import dev.nomark.sigil.ui.SigilToolWindowFactory
import java.nio.file.Files

class ScanSelectionAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return

        val selectedText = FileEditorManager.getInstance(project)
            .selectedTextEditor
            ?.selectionModel
            ?.selectedText

        if (selectedText.isNullOrEmpty()) {
            NotificationGroupManager.getInstance()
                .getNotificationGroup("Sigil")
                .createNotification(
                    "Sigil: No Selection",
                    "No text selected. Please highlight code to scan.",
                    NotificationType.WARNING
                )
                .notify(project)
            return
        }

        val runner = SigilRunner(project)

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Sigil: Scanning selection...", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    val tempFile = Files.createTempFile("sigil-snippet-", ".txt")
                    try {
                        Files.writeString(tempFile, selectedText)
                        val result = runner.scan(tempFile.toString())
                        SigilToolWindowFactory.updateFindings(project, result)

                        val type = when (result.verdict.lowercase()) {
                            "critical", "high_risk" -> NotificationType.ERROR
                            "medium_risk" -> NotificationType.WARNING
                            else -> NotificationType.INFORMATION
                        }

                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("Sigil")
                            .createNotification(
                                "Sigil: Selection Scan",
                                "${result.verdict} — ${result.findings.size} findings",
                                type
                            )
                            .notify(project)
                    } catch (ex: Exception) {
                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("Sigil")
                            .createNotification(
                                "Sigil Scan Failed",
                                ex.message ?: "Unknown error",
                                NotificationType.ERROR
                            )
                            .notify(project)
                    } finally {
                        Files.deleteIfExists(tempFile)
                    }
                }
            }
        )
    }

    override fun update(e: AnActionEvent) {
        val project = e.project ?: run {
            e.presentation.isEnabledAndVisible = false
            return
        }
        e.presentation.isEnabledAndVisible =
            FileEditorManager.getInstance(project).selectedTextEditor != null
    }
}
