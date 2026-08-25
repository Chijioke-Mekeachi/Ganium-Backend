package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"ganium/src/db"
	"ganium/src/models"
	"ganium/src/utils"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// genNumericOTP returns an n-digit numeric OTP as a zero-padded string.
func genNumericOTP(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil) // 10^n
	num, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	format := fmt.Sprintf("%%0%dd", n)
	return fmt.Sprintf(format, num.Int64()), nil
}

func RegisterController(data models.Register) (bool, string) {
	if err := db.CreateCollection("users"); err != nil {
		// ignore error if collection already exists
	}

	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")

	passwordHash, err := utils.HashPassword(data.Password)
	if err != nil {
		fmt.Println(err)
		return false, "Error hashing password"
	}

	var user models.Register
	err = collection.FindOne(context.Background(), bson.M{"email": data.Email}).Decode(&user)
	if err == nil {
		return false, "email already exists"
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		fmt.Println(err)
		return false, "database error"
	}

	otp, err := genNumericOTP(6)
	if err != nil {
		fmt.Println(err)
		return false, "failed to generate otp"
	}
	otpHash, err := utils.HashPassword(otp)
	if err != nil {
		fmt.Println(err)
		return false, "failed to hash otp"
	}

	otpExpiry := time.Now().Add(15 * time.Minute).Unix()

	_, err = collection.InsertOne(context.Background(), bson.M{
		"email":      data.Email,
		"password":   passwordHash,
		"isVerified": false,
		"otpHash":    otpHash,
		"otpExpiry":  otpExpiry,
	})
	if err != nil {
		fmt.Println(err)
		return false, "failed to register user"
	}

	// send OTP verification email
subject := "Verify your Ganium account"

// Plain-text fallback.
// This is important because some mail clients and spam filters
// inspect the text/plain version of the message.

// Professional responsive HTML email.
htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="color-scheme" content="light">
	<meta name="supported-color-schemes" content="light">
	<title>Verify your Ganium account</title>

	<style>
		body {
			margin: 0;
			padding: 0;
			background-color: #f4f6f8;
			font-family: Arial, Helvetica, sans-serif;
			color: #172033;
		}

		.wrapper {
			width: 100%%;
			padding: 40px 16px;
			box-sizing: border-box;
		}

		.container {
			max-width: 560px;
			margin: 0 auto;
			background: #ffffff;
			border-radius: 16px;
			overflow: hidden;
			border: 1px solid #e7eaf0;
			box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
		}

		.header {
			padding: 28px 32px;
			background: #111827;
			text-align: center;
		}

		.logo {
			display: inline-block;
			font-size: 26px;
			font-weight: 700;
			letter-spacing: -0.5px;
			color: #ffffff;
			text-decoration: none;
		}

		.logo-dot {
			color: #6366f1;
		}

		.content {
			padding: 38px 36px;
		}

		.title {
			margin: 0 0 14px;
			font-size: 26px;
			line-height: 1.3;
			font-weight: 700;
			color: #111827;
		}

		.text {
			margin: 0 0 18px;
			font-size: 15px;
			line-height: 1.7;
			color: #4b5563;
		}

		.otp-wrapper {
			margin: 30px 0;
			padding: 24px;
			background: #f8fafc;
			border: 1px solid #e5e7eb;
			border-radius: 12px;
			text-align: center;
		}

		.otp-label {
			margin-bottom: 10px;
			font-size: 12px;
			font-weight: 700;
			letter-spacing: 1px;
			text-transform: uppercase;
			color: #6b7280;
		}

		.otp {
			font-size: 34px;
			font-weight: 700;
			letter-spacing: 8px;
			color: #111827;
			font-family: Arial, Helvetica, sans-serif;
		}

		.expiry {
			margin-top: 12px;
			font-size: 13px;
			color: #6b7280;
		}

		.security {
			margin-top: 28px;
			padding: 18px;
			background: #f9fafb;
			border-left: 4px solid #6366f1;
			border-radius: 8px;
		}

		.security-title {
			margin: 0 0 8px;
			font-size: 14px;
			font-weight: 700;
			color: #374151;
		}

		.security-text {
			margin: 0;
			font-size: 13px;
			line-height: 1.6;
			color: #6b7280;
		}

		.footer {
			padding: 24px 32px;
			border-top: 1px solid #edf0f3;
			text-align: center;
			background: #fafbfc;
		}

		.footer-text {
			margin: 0;
			font-size: 12px;
			line-height: 1.6;
			color: #9ca3af;
		}

		@media only screen and (max-width: 600px) {
			.wrapper {
				padding: 20px 10px;
			}

			.content {
				padding: 30px 22px;
			}

			.header {
				padding: 24px 20px;
			}

			.title {
				font-size: 23px;
			}

			.otp {
				font-size: 29px;
				letter-spacing: 6px;
			}

			.footer {
				padding: 22px 18px;
			}
		}
	</style>
</head>

<body>
	<div class="wrapper">
		<div class="container">

			<!-- Header -->
			<div class="header">
				<div class="logo">
					Ganium<span class="logo-dot">.</span>
				</div>
			</div>

			<!-- Main content -->
			<div class="content">

				<h1 class="title">
					Verify your email address
				</h1>

				<p class="text">
					Thanks for creating your Ganium account.
					Please use the verification code below to confirm
					that this email address belongs to you.
				</p>

				<!-- OTP -->
				<div class="otp-wrapper">
					<div class="otp-label">
						Verification code
					</div>

					<div class="otp">
						%s
					</div>

					<div class="expiry">
						This code expires in 15 minutes.
					</div>
				</div>

				<p class="text">
					Enter this code in the Ganium app to complete
					your account verification.
				</p>

				<!-- Security information -->
				<div class="security">
					<p class="security-title">
						Keep your account secure
					</p>

					<p class="security-text">
						Never share this verification code with anyone.
						Ganium support will never ask you for this code.
						If you did not create a Ganium account, you can
						safely ignore this email.
					</p>
				</div>

			</div>

			<!-- Footer -->
			<div class="footer">
				<p class="footer-text">
					This is an automated message from Ganium.
					Please do not reply to this email.
					<br><br>
					© %d Ganium. All rights reserved.
				</p>
			</div>

		</div>
	</div>
</body>
</html>`, otp, time.Now().Year())

if err := utils.SendEmail(
	data.Email,
	subject,
	htmlBody,
); err != nil {
	fmt.Println("warning: failed to send otp email:", err)
	// Don't fail registration because of email delivery.
}

	return true, "User registered successfully; OTP sent to email"
}
