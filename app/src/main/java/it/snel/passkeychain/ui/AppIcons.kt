package it.snel.passkeychain.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.vectorResource
import it.snel.passkeychain.R

/**
 * The Material "Rounded" icons this app uses that are not in the small
 * material-icons-core set. They live in res/drawable (copied from
 * github.com/google/material-design-icons, Apache License 2.0), so the app
 * does not need material-icons-extended, which is ~25 MB of code in an
 * unshrunk debug build.
 */
object AppIcons {
    val ChevronRight: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_chevron_right)
    val ContentCopy: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_content_copy)
    val Event: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_event)
    val FileDownload: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_file_download)
    val FileUpload: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_file_upload)
    val Key: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_key)
    val Language: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_language)
    val QrCode2: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_qr_code_2)
    val QrCodeScanner: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_qr_code_scanner)
    val Shield: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_shield)
    val SystemUpdate: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_system_update)
    val Tag: ImageVector @Composable get() = ImageVector.vectorResource(R.drawable.ic_tag)
}
