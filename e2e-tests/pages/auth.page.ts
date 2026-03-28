import { expect, Page } from '@playwright/test';

/**
 * Page Object Model for Abstrauth authentication pages
 */
export class AuthPage {
    constructor(private page: Page) {}

    /**
     * Sign in with email and password
     */
    async signIn(email: string, password: string): Promise<void> {
        console.log(`Signing in as ${email}...`);
        
        // Wait for sign-in page to load
        await expect(this.page.getByRole('heading', { name: 'Sign in' })).toBeVisible({ timeout: 10000 });
        
        // Fill in credentials
        await this.page.getByRole('textbox', { name: 'Email' }).fill(email);
        await this.page.getByRole('textbox', { name: 'Password' }).fill(password);
        
        // Click sign-in button (use exact match to avoid matching "Sign in with Google")
        await this.page.getByRole('button', { name: 'Sign in', exact: true }).click();
        
        console.log('Sign-in form submitted');
    }

    /**
     * Approve application access (without remembering for 30 days)
     */
    async approveApplication(): Promise<void> {
        console.log('Approving application access...');
        
        // Wait for approval page
        await expect(this.page.getByRole('heading', { name: 'Approve Application' })).toBeVisible({ timeout: 10000 });
        
        // Ensure "Remember for 30 days" is NOT checked
        const rememberCheckbox = this.page.getByRole('checkbox', { name: /Remember this approval/i });
        if (await rememberCheckbox.isChecked()) {
            await rememberCheckbox.uncheck();
            console.log('Unchecked "Remember for 30 days"');
        }
        
        // Click Approve button
        await this.page.getByRole('button', { name: 'Approve' }).click();
        
        console.log('Application approved');
    }

    /**
     * Complete full authentication flow
     */
    async authenticate(email: string, password: string): Promise<void> {
        console.log('Starting authentication flow...');
        await this.signIn(email, password);
        await this.approveApplication();
        console.log('Authentication complete');
    }
}
