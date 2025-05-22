<?php
error_reporting(0);
session_start();

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

include('assets/config.php');
require 'phpmailer/src/Exception.php';
require 'phpmailer/src/PHPMailer.php';
require 'phpmailer/src/SMTP.php';

$response = ['status' => '', 'message' => ''];

function normalizeEmail($email) {
    $email = strtolower($email);
    list($local, $domain) = explode('@', $email, 2);
    $publicDomains = ['gmail.com', 'googlemail.com', 'yahoo.com', 'outlook.com'];
    if (in_array($domain, $publicDomains)) {
        $local = explode('+', $local)[0];
    }
    return $local . '@' . $domain;
}

function domain_exists($email, $record = 'MX') {
    list($user, $domain) = explode('@', $email);
    return checkdnsrr($domain, $record);
}

function isRateLimited($conn, $email, $ip) {
    $stmt = $conn->prepare("SELECT COUNT(*) as req_count FROM email_otp_requests WHERE email = ? AND requested_at > (NOW() - INTERVAL 10 MINUTE)");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return $result['req_count'] >= 3;
}

function logOtpRequest($conn, $email, $ip) {
    $stmt = $conn->prepare("INSERT INTO email_otp_requests (email, ip_address, requested_at) VALUES (?, ?, NOW())");
    $stmt->bind_param("ss", $email, $ip);
    $stmt->execute();
}

function generateOTP() {
    return rand(1000000, 9999999);
}

function getEmailObject($receiver, $otp) {
    $title = 'OTP Verification Email';
    $message = "<h3>OTP Verification</h3><p>Your one time password is <b>{$otp}</b>.</p><p>This email is computer generated. Do not reply.</p>";

    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = 'smtp.gmail.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'erp.schoolmanagementsystem@gmail.com';
    $mail->Password = 'whqbysomdhdjthvr'; // Replace with env var in production
    $mail->SMTPSecure = 'tls';
    $mail->Port = 587;

    $mail->setFrom('erp.schoolmanagementsystem@gmail.com');
    $mail->addAddress($receiver);
    $mail->isHTML(true);
    $mail->Subject = $title;
    $mail->Body = $message;

    return $mail;
}

if (isset($_POST['otp'], $_POST['email'])) {
    $email = normalizeEmail(mysqli_real_escape_string($conn, $_POST['email']));
    $otp = mysqli_real_escape_string($conn, $_POST['otp']);
    $generatedOtp = $_SESSION['otp'];

    if ($otp === $generatedOtp) {
        $response['status'] = 'success';
        $response['message'] = 'OTP matched';
        unset($_SESSION['otp']);
    } else {
        $response['status'] = 'ERROR';
        $response['message'] = 'Invalid OTP!';
    }

} elseif (isset($_POST['password'], $_POST['email'])) {
    $email = normalizeEmail(mysqli_real_escape_string($conn, $_POST['email']));
    $password = mysqli_real_escape_string($conn, $_POST['password']);
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    $stmt2 = mysqli_prepare($conn, "UPDATE users SET password_hash = ? WHERE email = ?");
    mysqli_stmt_bind_param($stmt2, "ss", $passwordHash, $email);
    $stmt3 = mysqli_prepare($conn, "SELECT id FROM users WHERE email = ?");
    mysqli_stmt_bind_param($stmt3, "s", $email);
    mysqli_stmt_execute($stmt3);
    $result = mysqli_stmt_get_result($stmt3);

    if (mysqli_stmt_execute($stmt2) && mysqli_num_rows($result) > 0) {
        $row = mysqli_fetch_assoc($result);
        $_SESSION['uid'] = $row['id'];
        $response['status'] = 'update_success';
        $response['message'] = 'Password successfully updated';
    } else {
        $response['status'] = 'Error';
        $response['message'] = 'Unable to update password';
    }

    mysqli_stmt_close($stmt2);
    mysqli_stmt_close($stmt3);

} elseif (isset($_POST['email'])) {
    $email = normalizeEmail(mysqli_real_escape_string($conn, $_POST['email']));
    $ip = $_SERVER['REMOTE_ADDR'];

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !domain_exists($email)) {
        $response['status'] = 'ERROR';
        $response['message'] = 'Invalid email!';
        echo json_encode($response);
        exit;
    }

    if (isRateLimited($conn, $email, $ip)) {
        $response['status'] = 'ERROR';
        $response['message'] = 'Too many OTP requests. Try again later.';
        echo json_encode($response);
        exit;
    }

    $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE email = ?");
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) > 0) {
        $OTP = generateOTP();
        $mail = getEmailObject($email, $OTP);

        try {
            $mail->send();
            $_SESSION['otp'] = $OTP;
            logOtpRequest($conn, $email, $ip);
            $response['status'] = 'success';
            $response['email'] = $email;
        } catch (Exception $e) {
            $response['status'] = 'ERROR';
            $response['message'] = 'Failed to send email';
        }
    } else {
        $response['status'] = 'ERROR';
        $response['message'] = 'Email not found';
    }

    mysqli_stmt_close($stmt);
} else {
    $response['status'] = 'ERROR';
    $response['message'] = 'Invalid request';
}

echo json_encode($response);
?>
