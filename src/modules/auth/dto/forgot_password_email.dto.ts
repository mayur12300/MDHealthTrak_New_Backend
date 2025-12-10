import { IsOptional, IsString, IsEmail } from 'class-validator';

export class ForgotPasswordEmailDto {
  @IsOptional()
  @IsString()
  readonly userId?: string;

  @IsOptional()
  @IsEmail()
  readonly email?: string;
}
