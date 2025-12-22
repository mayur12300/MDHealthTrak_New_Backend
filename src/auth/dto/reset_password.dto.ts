import {
  IsString,
  IsEmail,
  IsNotEmpty,
  ValidateIf,
  MinLength,
} from 'class-validator';

export class ResetPasswordDto {
  // Require at least one identifier
  @ValidateIf((o) => !o.email && !o.mobile)
  @IsString()
  @IsNotEmpty()
  readonly user_id?: string;

  @ValidateIf((o) => !o.email && !o.mobile)
  @IsString()
  @IsNotEmpty()
  readonly lookup_id?: string;

  @ValidateIf((o) => !o.email && !o.user_id)
  @IsString()
  @IsNotEmpty()
  readonly mobile?: string;

  @ValidateIf((o) => !o.mobile && !o.user_id)
  @IsEmail()
  @IsNotEmpty()
  readonly email?: string;

  // OTP is mandatory
  @IsString()
  @IsNotEmpty()
  readonly otp: string;

  // Password rules
  @IsString()
  @MinLength(6)
  readonly password: string;

  // Must match password
  @IsString()
  @IsNotEmpty()
  readonly confirm_password: string;
}
