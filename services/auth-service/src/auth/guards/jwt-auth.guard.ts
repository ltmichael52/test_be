import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth.service';

// test
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private readonly authService: AuthService) {
    super();
  }

  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers?.authorization as string | undefined;
    const token = authHeader?.replace(/^Bearer\s+/i, '') ?? '';

    if (!token) {
      throw new UnauthorizedException('Missing token');
    }

    const revoked = await this.authService.isTokenRevoked(token);
    if (revoked) {
      throw new UnauthorizedException('Token revoked');
    }

    return (await super.canActivate(context)) as boolean;
  }
}
