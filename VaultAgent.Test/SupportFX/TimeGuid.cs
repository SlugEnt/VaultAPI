/*
 * Copyright 2018 Scott Herrmann

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.SupportFX
{
	/// <summary>
	/// Converts a time - 15:30:56 into a TimeGuid object represented as 3 characters - for instance - Ld7
	/// </summary>
	public class TimeGuid
	{
		private static short rA = 65;
		private static short rZ = 90;
		private static short ra = 97;
		private static short rz = 122;
		private static short r0 = 48;
		private static short r9 = 57;



		private static char ConvertHoursToChar(int hours) {
			int start = rA + hours;
			return Convert.ToChar(start);
		}

		private static char ConvertMinutesToChar(int minutes) {
			return ConvertTimeUnit60ToChar(minutes);
		}

		private static char ConvertSecondsToChar(int seconds) {
			return ConvertTimeUnit60ToChar(seconds);
		}

		private static char ConvertTimeUnit60ToChar(int value) {
			if (value < 26) { return Convert.ToChar(rA + value); }
			else if (value < 52) { return Convert.ToChar(ra + (value - 26)); }
			else { return Convert.ToChar(r0 + (value - 52)); }

		}



		/// <summary>
		/// Converts the time part of the dateTime to a TimeGuid object (HMS)
		/// </summary>
		/// <param name="d">DateTime object containing the time you wish to convert.</param>
		/// <returns></returns>
		public static string ConvertTimeToChar(DateTime d) {
			int hr = d.Hour;
			int min = d.Minute;
			int sec = d.Second;

			return (ConvertHoursToChar(hr).ToString() + ConvertMinutesToChar(min).ToString() + ConvertSecondsToChar(sec).ToString());
		}
	}
}
