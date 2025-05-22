<?php
session_start();
include('../assets/config.php');

if (isset($_SESSION['uid'])) {
    $userId = $_SESSION['uid'];
    $sql = "SELECT `role` FROM `users` WHERE `id` = ?";
    
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $userId);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);

    if ($row) {
        switch ($row['role']) {
            case 'admin':
                header("Location: ../admin_panel/dashboard.php");
                break;
            case 'owner':
                header("Location: ../owner_panel/index.php");
                break;
            case 'teacher':
                header("Location: ../teacher_panel/dashboard.php");
                break;
            case 'student':
                header("Location: ../student_panel/index.php");
                break;
            default:
                include('../assets/logout.php');
                header("Location: ../login.php");
        }
        exit();
    }
}
include('../assets/logout.php');
header("Location: ../login.php");
exit();
?>
