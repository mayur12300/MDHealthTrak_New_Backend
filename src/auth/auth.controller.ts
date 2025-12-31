import { Controller, Post, Body, Get, UseGuards, Req } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import * as dto from './dto';
import { AuthGuard } from '@nestjs/passport';

// @Controller('auth')
// export class AuthController {
//   @UseGuards(AuthGuard('jwt'))
//   @Get('profile')
//   getProfile(@Request() req) {
//     return req.user; // The validated user object from JwtStrategy.validate()
//   }
// }

@Controller('auth')
export class AuthController {
  constructor(private readonly service: AuthService) {}

  @Post('send-otp')
  async send_otp(@Body() dto: dto.SendOtpDto) {
    return this.service.sendOtp(dto);
  }

  @Post('verify-otp')
  verifyOtp(@Body() dto: dto.VerifyOtpDto) {
    return this.service.verifyOtp(
      dto.mobile,
      dto.email,
      dto.otp,
      dto.country_code,
    );
  }

  @Post('signup')
  signup(@Body() dto: dto.SignupDto, @Req() req: Request) {
    return this.service.signup(dto, req);
  }

  @Post('login/email')
  login(@Body() dto: dto.LoginDto, @Req() req: Request) {
    return this.service.login(dto, req);
  }

  @Post('send-otp-mobile')
  async send_otp_mobile(@Body() dto: dto.SendOtpDto) {
    return this.service.sendOtpMobile(dto);
  }

  @Post('login-otp')
  async loginWithOtp(@Body() dto: dto.LoginVerifyOtpDto, @Req() req: Request) {
    return this.service.verifyOtpAndLogin(dto, req);
  }

  @Post('logout')
  logout(@Body('session_id') sessionId: string) {
    return this.service.logout(sessionId);
  }

  @Post('forgot-password-mobile')
  async forgot_password_mobile(@Body() payload: dto.ForgotPasswordMobileDto) {
    return this.service.forgotPasswordMobile(payload);
  }

  @Post('forgot-password-email')
  async forgot_password_email(@Body() payload: dto.ForgotPasswordEmailDto) {
    return this.service.forgotPasswordEmail(payload);
  }

  @Post('reset-password')
  async reset_password(@Body() payload: dto.ResetPasswordDto) {
    return this.service.resetPassword(payload);
  }

  @Post('signup-set-password')
  async signup_set_password(@Body() payload: dto.SignupSetPasswordDto) {
    return this.service.signup_set_password(payload);
  }

  @Post('signup-google')
  async signup_google(
    @Body() payload: dto.SignupGoogleDto,
    @Req() req: Request,
  ) {
    const { idToken, role } = payload;
    return this.service.signup_google(idToken, role, req);
  }

  @Post('login-google')
  async loginGoogle(@Body() payload: dto.LoginGoogleDto, @Req() req: Request) {
    const { idToken, role } = payload;
    return this.service.login_google(idToken, role, req);
  }

  @Post('facebook/signup')
  signupFacebook(
    @Body('accessToken') accessToken: string,
    @Body('role') role: dto.UserRole,
    @Req() req: Request,
  ) {
    return this.service.signup_facebook(accessToken, role, req);
  }

  @Post('facebook/login')
  loginFacebook(
    @Body('accessToken') accessToken: string,
    @Body('role') role: dto.UserRole,
    @Req() req: Request,
  ) {
    return this.service.login_facebook(accessToken, role, req);
  }

  @Post('signup-apple')
  async signup_apple(
    @Body() payload: dto.SignupAppleDto,
    @Body('role') role: dto.UserRole,
    @Req() req: Request,
  ) {
    return this.service.signup_apple(payload.idToken, role, req);
  }

  @Post('login-apple')
  async login_apple(
    @Body() payload: dto.LoginAppleDto,
    @Body('role') role: dto.UserRole,
    @Req() req: Request,
  ) {
    return this.service.login_apple(payload.idToken, role, req);
  }

  @Post('login-send-otp')
  async login_send_otp(@Body() payload: dto.LoginSendOtpDto) {
    return this.service.login_send_otp(payload);
  }

  @Post('login-verify-otp')
  async login_verify_otp(@Body() payload: dto.LoginVerifyOtpDto) {
    return this.service.login_verify_otp(payload);
  }

  @Post('login-email-password')
  async login_email_password(@Body() payload: dto.LoginEmailPasswordDto) {
    return this.service.login_email_password(payload);
  }
}
