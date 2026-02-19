package dev.nomark.sigil.actions

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.ui.Messages
import dev.nomark.sigil.runner.SigilRunner
import dev.nomark.sigil.ui.SigilToolWindowFactory

class ScanPackageAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return

        val manager = Messages.showEditableChooseDialog(
            "Select package manager:",
            "Sigil: Scan Package",
            Messages.getQuestionIcon(),
            arrayOf("npm", "pip"),
            "npm",
            null
        ) ?: return

        val packageName = Messages.showInputDialog(
            project,
            "Enter $manager package name:",
            "Sigil: Scan Package",
            Messages.getQuestionIcon()
        ) ?: return

        if (packageName.isBlank()) return

        val runner = SigilRunner(project)

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Sigil: Scanning $manager package \"$packageName\"...", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        val result = runner.scanPackage(manager, packageName)
                        SigilToolWindowFactory.updateFindings(project, result)

                        val type = when (result.verdict.lowercase()) {
                            "critical", "high_risk" -> NotificationType.ERROR
                            "medium_risk" -> NotificationType.WARNING
                            else -> NotificationType.INFORMATION
                        }

                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("Sigil")
                            .createNotification(
                                "Sigil: $manager/$packageName",
                                "${result.verdict} — ${result.findings.size} findings (score ${result.score})",
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
