import { expect, Page, Locator } from '@playwright/test';

/**
 * Page Object Model for the main traffic monitoring page
 */
export class TrafficPage {
    constructor(private page: Page) {}

    // Locators
    private get beginTimeInput(): Locator {
        return this.page.getByLabel('Begin Time (Inclusive)');
    }

    private get endTimeInput(): Locator {
        return this.page.getByLabel('End Time (Exclusive)');
    }

    private get loadDataButton(): Locator {
        return this.page.getByRole('button', { name: 'Load Data' });
    }

    private get acceptListSection(): Locator {
        return this.page.getByRole('heading', { name: /Accept-List Filters/i });
    }

    private get addFilterButton(): Locator {
        return this.page.getByRole('button', { name: '+ Add Filter' });
    }

    private get filterPatternInput(): Locator {
        return this.page.locator('#new-filter-pattern');
    }

    private get filterDescriptionInput(): Locator {
        return this.page.locator('#new-filter-description');
    }

    private get saveFilterButton(): Locator {
        return this.page.getByRole('button', { name: 'Save', exact: true });
    }

    private get cancelFilterButton(): Locator {
        return this.page.getByRole('button', { name: 'Cancel' });
    }

    /**
     * Navigate to the traffic page
     */
    async goto(): Promise<void> {
        console.log('Navigating to traffic page...');
        await this.page.goto('/');
        console.log('On traffic page');
    }

    /**
     * Wait for authentication to complete and page to load
     */
    async waitForAuthenticated(): Promise<void> {
        console.log('Waiting for authenticated state...');
        // Wait for sign-out link to appear (indicates authenticated)
        await expect(this.page.getByRole('link', { name: /Sign out/i })).toBeVisible({ timeout: 15000 });
        console.log('User is authenticated');
    }

    /**
     * Click sign-in button to start authentication flow
     */
    async clickSignIn(): Promise<void> {
        console.log('Clicking sign-in button...');
        await this.page.getByRole('button', { name: 'Sign In' }).click();
        console.log('Sign-in button clicked');
    }

    /**
     * Load traffic data for a specific time range
     */
    async loadTrafficData(beginTime: string, endTime: string): Promise<void> {
        console.log(`Loading traffic data from ${beginTime} to ${endTime}...`);
        
        await this.beginTimeInput.fill(beginTime);
        await this.endTimeInput.fill(endTime);
        await this.loadDataButton.click();
        
        // Wait for data to load (stats should update)
        await this.page.waitForTimeout(1000);
        
        console.log('Traffic data loaded');
    }

    /**
     * Get the number of visible IPs from the stats
     */
    async getVisibleIpCount(): Promise<number> {
        // Check if there's a filtered count displayed
        const filteredText = await this.page.locator('#stat-ips-filtered').textContent();
        if (filteredText) {
            const match = filteredText.match(/\((\d+) visible\)/);
            if (match) {
                return parseInt(match[1]);
            }
        }
        // If no filter is active, return the total count
        return this.getTotalIpCount();
    }

    /**
     * Get the total number of IPs (including hidden ones)
     */
    async getTotalIpCount(): Promise<number> {
        const statsText = await this.page.locator('#stat-ips').textContent();
        return statsText ? parseInt(statsText.trim()) : 0;
    }

    /**
     * Expand the Accept-List Filters section
     */
    async expandAcceptListSection(): Promise<void> {
        console.log('Expanding Accept-List section...');
        
        // Check if already expanded by looking for the add button
        const isExpanded = await this.addFilterButton.isVisible().catch(() => false);
        
        if (!isExpanded) {
            await this.acceptListSection.click();
            await expect(this.addFilterButton).toBeVisible({ timeout: 5000 });
            console.log('Accept-List section expanded');
        } else {
            console.log('Accept-List section already expanded');
        }
    }

    /**
     * Ensure accept-list is enabled
     */
    async ensureAcceptListEnabled(): Promise<void> {
        const checkbox = this.page.locator('#accept-list-enabled');
        const isChecked = await checkbox.isChecked();
        if (!isChecked) {
            console.log('Enabling accept-list...');
            await checkbox.check({ force: true });
            await this.page.waitForTimeout(500);
        } else {
            console.log('Accept-list already enabled');
        }
    }

    /**
     * Disable accept-list filtering
     */
    async disableAcceptList(): Promise<void> {
        console.log('Disabling accept-list...');
        await this.expandAcceptListSection();
        const checkbox = this.page.locator('#accept-list-enabled');
        const isChecked = await checkbox.isChecked();
        if (isChecked) {
            // Click on the text next to the toggle to toggle it
            await this.page.getByText('Enable Accept-List (Hide Matching Traffic)').click();
            await this.page.waitForTimeout(500);
            console.log('Accept-list disabled');
        } else {
            console.log('Accept-list already disabled');
        }
    }

    /**
     * Add a new accept-list filter
     */
    async addAcceptListFilter(pattern: string, description: string): Promise<void> {
        console.log(`Adding accept-list filter: ${pattern}`);
        
        // Ensure section is expanded
        await this.expandAcceptListSection();
        
        // Ensure accept-list is enabled
        await this.ensureAcceptListEnabled();
        
        // Click add filter button
        await this.addFilterButton.click();
        
        // Wait for form to appear
        await expect(this.filterPatternInput).toBeVisible({ timeout: 5000 });
        
        // Fill in the form
        await this.filterPatternInput.fill(pattern);
        await this.filterDescriptionInput.fill(description);
        
        // Save the filter
        await this.saveFilterButton.click();
        
        // Wait for success message
        await expect(this.page.getByText('Filter added successfully')).toBeVisible({ timeout: 5000 });
        
        console.log('Filter added successfully');
    }

    /**
     * Edit an existing filter by its pattern and current description
     */
    async editFilter(originalPattern: string, currentDescription: string, newDescription: string): Promise<void> {
        console.log(`Editing filter with pattern: ${originalPattern}`);
        
        // Find the specific filter item by both pattern and description
        const filterItem = this.page.locator('.filter-item')
            .filter({ hasText: originalPattern })
            .filter({ hasText: currentDescription })
            .first();
        
        await filterItem.getByRole('button', { name: 'Edit' }).click();
        
        // Wait for edit form to appear
        const editDescriptionInput = filterItem.getByRole('textbox', { name: /Description/i });
        await expect(editDescriptionInput).toBeVisible({ timeout: 5000 });
        
        // Update the description
        await editDescriptionInput.fill(newDescription);
        
        // Save the changes
        await filterItem.getByRole('button', { name: 'Save' }).click();
        
        // Wait a moment for the save to complete
        await this.page.waitForTimeout(1000);
        
        console.log('Filter edited successfully');
    }

    /**
     * Delete a filter by its pattern and description
     */
    async deleteFilter(pattern: string, description: string): Promise<void> {
        console.log(`Deleting filter with pattern: ${pattern}`);
        
        // Find the specific filter item by both pattern and description
        const filterItem = this.page.locator('.filter-item')
            .filter({ hasText: pattern })
            .filter({ hasText: description })
            .first();
        
        // Set up dialog handler before clicking delete
        this.page.once('dialog', async dialog => {
            console.log(`Confirming deletion: ${dialog.message()}`);
            await dialog.accept();
        });
        
        await filterItem.getByRole('button', { name: 'Delete' }).click();
        
        // Wait for the filter to be removed
        await expect(filterItem).not.toBeVisible({ timeout: 5000 });
        
        console.log('Filter deleted successfully');
    }

    /**
     * Verify a filter exists with the given pattern and description
     */
    async verifyFilterExists(pattern: string, description: string): Promise<void> {
        console.log(`Verifying filter exists: ${pattern}`);
        
        // Find filter items that contain both the pattern and description
        const filterItem = this.page.locator('.filter-item').filter({ hasText: pattern }).filter({ hasText: description });
        await expect(filterItem.first()).toBeVisible({ timeout: 5000 });
        
        console.log('Filter verified');
    }

    /**
     * Verify a filter does not exist with the given pattern and description
     */
    async verifyFilterNotExists(pattern: string, description: string): Promise<void> {
        console.log(`Verifying filter does not exist: ${pattern} - ${description}`);
        
        const filterItem = this.page.locator('.filter-item')
            .filter({ hasText: pattern })
            .filter({ hasText: description });
        await expect(filterItem).not.toBeVisible();
        
        console.log('Filter confirmed not to exist');
    }

    /**
     * Get all visible IP addresses from the traffic table
     */
    async getVisibleIpAddresses(): Promise<string[]> {
        // Select all rows in the traffic table body
        const rows = this.page.locator('tbody tr');
        const count = await rows.count();
        const ips: string[] = [];
        
        for (let i = 0; i < count; i++) {
            const row = rows.nth(i);
            // Check if row is actually visible (not hidden by CSS)
            const isVisible = await row.isVisible();
            if (isVisible) {
                const ipCell = row.locator('code').first();
                const ip = await ipCell.textContent();
                if (ip) {
                    ips.push(ip);
                }
            }
        }
        
        console.log(`Found ${ips.length} visible IPs: ${ips.join(', ')}`);
        return ips;
    }
}
