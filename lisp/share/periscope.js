/* Periscope - Network auditing tool
 * Copyright (C) 2009 Sam Alves <samalves@ele.uri.edu>
 * Copyright (C) 2009 Harry Bock <hbock@ele.uri.edu>
 
 * This file is part of Periscope.

 * periscope is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * periscope is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with periscope; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

function loginFocus() 
{
    document.getElementById("login").focus();
}

function reportById(index)
{
    return document.getElementById("r".concat(index.toString()));
}

function displaySingleReport(index)
{
    i = 0;
    while(hideReport(i))
	i++;

    showReport(index);
}

function showReport(index)
{
    report = reportById(index);

    if(report != null) {
	report.style.display = "block";
	return true;
    }
    return false;
}

function hideReport(index)
{
    report = reportById(index);

    if(report != null) {
	report.style.display = "none";
	return true;
    }
    return false;
}

function checkFilters()
{
    rows = document.getElementById("available-filters").getElementsByTagName("tr");
    removing = "";
    
    /* Locate filters to be removed, if any. */
    for(i = 1; i < rows.length; i++) {
	inputs = rows[i].getElementsByTagName("input");
	removeCheck = inputs[3];

	if(removeCheck.checked) {
	    title = inputs[1].value;
	    removing += "\t" + title + "\n";
	}
    }
    /* Confirm if removing... */
    if(removing != "") {
	return confirm("Deleting the following filters:\n" +
		       removing + "\n" +
		       "Removing these filters will recursively delete all reports associated " +
		       "with them. Are you sure you wish to do this?");
    }
    return true;
}