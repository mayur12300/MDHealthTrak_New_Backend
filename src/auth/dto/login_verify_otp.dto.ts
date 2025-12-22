import {
  IsString,
  IsEmail,
  IsNotEmpty,
  ValidateIf,
  IsOptional,
} from 'class-validator';

export class LoginVerifyOtpDto {
  @ValidateIf((o) => !o.email)
  @IsString()
  @IsNotEmpty()
  readonly mobile?: string;

  @ValidateIf((o) => !o.mobile)
  @IsEmail()
  @IsNotEmpty()
  readonly email?: string;

  @IsString()
  @IsNotEmpty()
  readonly otp: string;

  @IsOptional()
  @IsString()
  readonly country_code?: string;
}
