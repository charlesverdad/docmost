import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Patch,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
  Logger,
} from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { AuthService } from './services/auth.service';
import { SetupGuard } from './guards/setup.guard';
import { EnvironmentService } from '../../integrations/environment/environment.service';
import { CreateAdminUserDto } from './dto/create-admin-user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { AuthUser } from '../../common/decorators/auth-user.decorator';
import { User, Workspace } from '@docmost/db/types/entity.types';
import { AuthWorkspace } from '../../common/decorators/auth-workspace.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { PasswordResetDto } from './dto/password-reset.dto';
import { VerifyUserTokenDto } from './dto/verify-user-token.dto';
import { FastifyReply, FastifyRequest } from 'fastify';
import { validateSsoEnforcement } from './auth.util';
import { ModuleRef } from '@nestjs/core';
import { UpdateOidcConfigDto } from './dto/update-oidc.dto';
import { OidcConfigDto } from './dto/oidc-config.dto';
import { UpdateDomainsDto } from './dto/update-domains.dto';
import { Issuer } from 'openid-client';
import { UserRole } from '../../common/helpers/types/permission';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private authService: AuthService,
    private environmentService: EnvironmentService,
    private moduleRef: ModuleRef,
  ) {}

  @Get('cb')
  @HttpCode(HttpStatus.TEMPORARY_REDIRECT)
  async callback(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const token = await this.authService.oidcLogin(req);
    this.setAuthCookie(reply, token);
    return reply.redirect(`${this.environmentService.getAppUrl()}/home`);
  }

  @Get('oauth-redirect')
  @HttpCode(HttpStatus.TEMPORARY_REDIRECT)
  async oauthRedirect(
    @AuthWorkspace() workspace: Workspace,
    @Res() reply: FastifyReply,
  ) {
    const redirectUri = `${this.environmentService.getAppUrl()}/api/auth/cb`;

    if (!workspace.oidcIssuerUrl) {
      return reply.redirect(`${this.environmentService.getAppUrl()}/login`);
    }

    const issuer = await Issuer.discover(workspace.oidcIssuerUrl);

    if (!issuer.metadata.authorization_endpoint || !workspace.oidcClientId) {
      return reply.redirect(`${this.environmentService.getAppUrl()}/login`);
    }

    const authRedirect =
      `${issuer.metadata.authorization_endpoint}` +
      `?response_type=code` +
      `&client_id=${workspace.oidcClientId}` +
      `&redirect_uri=${redirectUri}` +
      `&scope=openid profile email` +
      `&state=${workspace.id}`;

    return reply.redirect(authRedirect);
  }

  @Get('oidc-public-config')
  @HttpCode(HttpStatus.OK)
  async oidcPublicConfig(@AuthWorkspace() workspace: Workspace) {
    return {
      enabled: workspace.oidcEnabled,
      buttonName: workspace.oidcButtonName,
    };
  }

  @Get('oidc-config')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async oauthConfig(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ): Promise<OidcConfigDto> {
    if (user.role !== UserRole.ADMIN && user.role !== UserRole.OWNER) {
      throw new UnauthorizedException();
    }

    return {
      enabled: workspace.oidcEnabled,
      issuerUrl: workspace.oidcIssuerUrl,
      clientId: workspace.oidcClientId,
      buttonName: workspace.oidcButtonName,
      jitEnabled: workspace.oidcJitEnabled,
    };
  }

  @Patch('oidc-config')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async updateOidcConfig(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
    @Body() dto: UpdateOidcConfigDto,
  ): Promise<OidcConfigDto> {
    if (user.role !== UserRole.ADMIN && user.role !== UserRole.OWNER) {
      throw new UnauthorizedException();
    }

    return this.authService.updateOidcConfig(dto, workspace.id);
  }

  @Get('approved-domains')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async getApprovedDomains(@AuthWorkspace() workspace: Workspace) {
    return { domains: workspace.approvedDomains };
  }

  @Patch('approved-domains')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async updateApprovedDomains(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
    @Body() dto: UpdateDomainsDto,
  ) {
    if (user.role !== UserRole.ADMIN && user.role !== UserRole.OWNER) {
      throw new UnauthorizedException();
    }

    const domains = await this.authService.updateApprovedDomains(
      dto.domains,
      workspace.id,
    );

    return { domains };
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @AuthWorkspace() workspace: Workspace,
    @Res({ passthrough: true }) res: FastifyReply,
    @Body() loginInput: LoginDto,
  ) {
    validateSsoEnforcement(workspace);

    let MfaModule: any;
    let isMfaModuleReady = false;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      MfaModule = require('./../../ee/mfa/services/mfa.service');
      isMfaModuleReady = true;
    } catch (err) {
      this.logger.debug(
        'MFA module requested but EE module not bundled in this build',
      );
      isMfaModuleReady = false;
    }
    if (isMfaModuleReady) {
      const mfaService = this.moduleRef.get(MfaModule.MfaService, {
        strict: false,
      });

      const mfaResult = await mfaService.checkMfaRequirements(
        loginInput,
        workspace,
        res,
      );

      if (mfaResult) {
        if (mfaResult.userHasMfa || mfaResult.requiresMfaSetup) {
          return {
            userHasMfa: mfaResult.userHasMfa,
            requiresMfaSetup: mfaResult.requiresMfaSetup,
            isMfaEnforced: mfaResult.isMfaEnforced,
          };
        } else if (mfaResult.authToken) {
          this.setAuthCookie(res, mfaResult.authToken);
          return;
        }
      }
    }

    const authToken = await this.authService.login(loginInput, workspace.id);
    this.setAuthCookie(res, authToken);
  }

  @UseGuards(SetupGuard)
  @HttpCode(HttpStatus.OK)
  @Post('setup')
  async setupWorkspace(
    @Res({ passthrough: true }) res: FastifyReply,
    @Body() createAdminUserDto: CreateAdminUserDto,
  ) {
    if (this.environmentService.isCloud()) throw new NotFoundException();

    const { authToken } = await this.authService.setup(createAdminUserDto);
    this.setAuthCookie(res, authToken);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('change-password')
  async changePassword(
    @Body() dto: ChangePasswordDto,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    return this.authService.changePassword(dto, user.id, workspace.id);
  }

  @HttpCode(HttpStatus.OK)
  @Post('forgot-password')
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @AuthWorkspace() workspace: Workspace,
  ) {
    validateSsoEnforcement(workspace);
    return this.authService.forgotPassword(forgotPasswordDto, workspace);
  }

  @HttpCode(HttpStatus.OK)
  @Post('password-reset')
  async passwordReset(
    @Res({ passthrough: true }) res: FastifyReply,
    @Body() passwordResetDto: PasswordResetDto,
    @AuthWorkspace() workspace: Workspace,
  ) {
    const result = await this.authService.passwordReset(
      passwordResetDto,
      workspace,
    );

    if (result.requiresLogin) {
      return {
        requiresLogin: true,
      };
    }

    this.setAuthCookie(res, result.authToken);
    return {
      requiresLogin: false,
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('verify-token')
  async verifyResetToken(
    @Body() verifyUserTokenDto: VerifyUserTokenDto,
    @AuthWorkspace() workspace: Workspace,
  ) {
    return this.authService.verifyUserToken(verifyUserTokenDto, workspace.id);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('collab-token')
  async collabToken(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    return this.authService.getCollabToken(user, workspace.id);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(@Res({ passthrough: true }) res: FastifyReply) {
    res.clearCookie('authToken');
  }

  setAuthCookie(res: FastifyReply, token: string) {
    res.setCookie('authToken', token, {
      httpOnly: true,
      path: '/',
      expires: this.environmentService.getCookieExpiresIn(),
      secure: this.environmentService.isHttps(),
    });
  }
}

