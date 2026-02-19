package dev.nomark.sigil.actions

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import dev.nomark.sigil.runner.SigilRunner
import dev.nomark.sigil.ui.SigilToolWindowFactory

class ScanProjectAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: return
        val runner = SigilRunner(project)

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Sigil: Scanning project...", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        val result = runner.scan(basePath)

                        // Update tool window
                        SigilToolWindowFactory.updateFindings(project, result)

                        // Notify
                        val type = when (result.verdict.lowercase()) {
                            "critical", "high_risk" -> NotificationType.ERROR
                            "medium_risk" -> NotificationType.WARNING
                            else -> NotificationType.INFORMATION
                        }

                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("Sigil")
                            .createNotification(
                                "Sigil Scan Complete",
                                "${result.verdict}: ${result.findings.size} findings " +
                                    "(score ${result.score}, ${result.filesScanned} files, " +
                                    "${result.durationMs}ms)",
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
}
