package dev.nomark.sigil.actions

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import dev.nomark.sigil.runner.SigilRunner
import dev.nomark.sigil.ui.SigilToolWindowFactory

class ScanFileAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val file = e.getData(CommonDataKeys.VIRTUAL_FILE) ?: return
        val runner = SigilRunner(project)

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Sigil: Scanning ${file.name}...", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        val result = runner.scan(file.path)
                        SigilToolWindowFactory.updateFindings(project, result)

                        val type = when (result.verdict.lowercase()) {
                            "critical", "high_risk" -> NotificationType.ERROR
                            "medium_risk" -> NotificationType.WARNING
                            else -> NotificationType.INFORMATION
                        }

                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("Sigil")
                            .createNotification(
                                "Sigil: ${file.name}",
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
                    }
                }
            }
        )
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabledAndVisible = e.getData(CommonDataKeys.VIRTUAL_FILE) != null
    }
}
