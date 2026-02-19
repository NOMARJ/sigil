package dev.nomark.sigil.actions

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import dev.nomark.sigil.runner.SigilRunner

class ClearCacheAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        try {
            SigilRunner(project).clearCache()
            NotificationGroupManager.getInstance()
                .getNotificationGroup("Sigil")
                .createNotification("Sigil", "Scan cache cleared.", NotificationType.INFORMATION)
                .notify(project)
        } catch (ex: Exception) {
            NotificationGroupManager.getInstance()
                .getNotificationGroup("Sigil")
                .createNotification("Sigil", "Failed to clear cache: ${ex.message}", NotificationType.ERROR)
                .notify(project)
        }
    }
}
