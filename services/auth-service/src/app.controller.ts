import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { Roles } from './auth/guards/roles.decorator';
import { RolesGuard } from './auth/guards/roles.guard';

@Controller('me')
export class AppController {
  @Get()
  root() {
    return 'OK';
  }

  @Get('health')
  health() {
    return 'OK';
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  me() {
    return { ok: true };
  }

  @Get('admin')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  adminOnly() {
    return { ok: true, role: 'admin' };
  }
}
