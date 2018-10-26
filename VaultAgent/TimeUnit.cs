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
using System.Linq;

namespace CommonFunctions
{

	/// <summary>
	/// Used to represent all valid TimeUnitTypes for the TimeUnit class.
	/// </summary>
	public enum TimeUnitTypes : byte { Seconds, Minutes, Hours, Days, Weeks };



	/// <summary>
	/// Represents a unit of time that is sometimes used to provide a more friendly human readable format.  The unit of time is represented as a string in the format
	/// [amount of units][unit value].  Where:
	///   [amount of units] is a whole number representing how many of the units this time represents.
	///   [TimeUnitType] is a single character which represents the unit value.  Valid values are:
	///      s - Seconds
	///      m - Minutes
	///      h - Hours
	///      d - Days
	///      w - Weeks
	///      
	///      Larger Unit Types are not allowed as they become invalid due to calendar variations (not all months are 30 days for instance, or leap year). 
	/// </summary>
	/// <example>6m - 6 minutes</example>
	/// <example>14h - 14 hours</example>
	/// <example>104d - 104 days</example>
	public struct TimeUnit
	{
		/// <summary>
		/// We store the base unit in seconds.  We use a double because the TimeSpan conversion functions all require doubles, so this avoids lots of casting to double.
		/// </summary>
		private double _seconds;

		/// <summary>
		/// The TimeUnitType that this represents.
		/// </summary>
		private TimeUnitTypes unitType;



		/// <summary>
		/// Takes a number of seconds and turns it into a TimeUnit value stored as seconds.
		/// </summary>
		/// <param name="seconds"></param>
		public TimeUnit(long seconds) {
			_seconds = (double)seconds;
			unitType = TimeUnitTypes.Seconds;
		}


		public TimeUnit(string timeValue) {
			// First get last character of string.  Must be a letter.
			int len = timeValue.Length;

			// Length must be > 2.
			if (len < 2) { throw new ArgumentException("timeValue", "The value of TimeValue must be in the format of <number><TimeType> Where TimeType is a single character."); }

			char timeIncrement = timeValue[len - 1];

			// Now get first part of string which is the numeric part.
			string timeDuration = new string(timeValue.TakeWhile(d => !Char.IsLetter(d)).ToArray());


			// Validate we have a number and ultimately convert into a double for storing.
			double valNum;
			long valNumL;
			if (!long.TryParse(timeDuration, out valNumL)) {
				throw new ArgumentException("timeValue", "Did not contain a valid numeric prefix.  Proper format is <Number><TimeType> where Number is an integer and TimeType is a single character.");
			}
			valNum = (double)valNumL;


			// To completely validate we have what they sent we build a new string from the 2 components and compare the 2.  Should be equal.
			string snew = valNumL.ToString() + timeIncrement;
			if (snew != timeValue) {
				string msg = String.Format("Argument is in an invalid format - [{0}].  Proper format is <Number><TimeType> where Number is an integer and TimeType is a single character.", timeValue);
				throw new ArgumentException("timeValue", msg);
			}


			// Now we just need to validate the time unit type is correct and convert to seconds.


			// Validate the unit of time is correct.
			switch (timeIncrement) {
				case 'd':
					unitType = TimeUnitTypes.Days;
					_seconds = ConvertDaysToSeconds(valNum);
					break;
				case 'm':
					unitType = TimeUnitTypes.Minutes;
					_seconds = ConvertMinutesToSeconds(valNum);
					break;
				case 'h':
					unitType = TimeUnitTypes.Hours;
					_seconds = ConvertHoursToSeconds(valNum);
					break;
				case 's':
					unitType = TimeUnitTypes.Seconds;
					_seconds = valNum;
					break;
				case 'w':
					unitType = TimeUnitTypes.Weeks;
					_seconds = ConvertDaysToSeconds((valNum * 7));
					break;
				default:
					throw new ArgumentException("Invalid TimeUnitType specified.  Must be one of s,m,h,d,w.");
			}
		}



		/// <summary>
		/// Prints out the the TimeUnit in long text.  Example: 6 Minutes.
		/// </summary>
		/// <returns>String representing the long textual value.</returns>
		public override string ToString() {
			string rs = String.Format("{0} {1}", GetUnits(unitType), unitType.ToString());
			return rs;
		}




		/// <summary>
		/// Returns the TimeUnit "native" value.  Example:  6m
		/// </summary>
		public string Value
		{
			get {
				string rs = String.Format("{0}{1}", GetUnits(unitType), GetUnitTypeAbbrev());
				return rs;
			}
		}



		/// <summary>
		/// Returns the numeric value of this TimeUnit.  If upon creation you specified a value of 9m (9 minutes) this function will return 9.
		/// </summary>
		public double ValueAsNumeric
		{
			get { return GetUnits(unitType); }
		}



		#region "Object Overrides"

		// Compare if the same.  Considered the same if number of seconds is same, does not matter what the TimeUnit type is.
		public static bool operator ==(TimeUnit x, TimeUnit y) {
			if (x._seconds == y._seconds) { return true; }
			else { return false; }
		}



		// Compare if not the same.  Considered the same if number of seconds is same, does not matter what the TimeUnit type is.
		public static bool operator !=(TimeUnit x, TimeUnit y) {
			if (x._seconds != y._seconds) { return true; }
			else { return false; }
		}


		public override bool Equals(object obj) {
			if (!(obj is TimeUnit)) { return false; }

			TimeUnit tu = (TimeUnit)obj;

			if (tu._seconds == _seconds) { return true; }
			else { return false; }
		}


		public override int GetHashCode() {
			return (int)_seconds;
		}

		#endregion



		#region "InFX Functions"     


		/// <summary>
		/// Returns the number of seconds this TimeUnit represents in Double format.
		/// </summary>
		public double InSecondsAsDouble
		{
			get {
				return GetUnits(TimeUnitTypes.Seconds);
			}
		}


		/// <summary>
		/// Returns the TimeUnit value as a double seconds string. IE.  125s
		/// </summary>
		public string InSecondsAsString
		{
			get {
				return (InSecondsAsDouble.ToString() + "s");
			}
		}


		/// <summary>
		/// Returns the TimeUnit in seconds format, but as a long value.
		/// </summary>
		public long InSecondsLong
		{
			get {
				return (long)GetUnits(TimeUnitTypes.Seconds);
			}
		}


		/// <summary>
		/// Returns the number of seconds this TimeUnit represents.
		/// </summary>
		/// <returns></returns>
		public double InMinutesAsDouble
		{
			get {
				return GetUnits(TimeUnitTypes.Minutes);
			}
		}


		/// <summary>
		///  Returns the TimeUnit in minutes as a string (ie. 6m)
		/// </summary>
		public string InMinutesAsString
		{
			get {
				return (InMinutesAsDouble.ToString() + "m");
			}
		}


		/// <summary>
		/// Returns the number of seconds this TimeUnit represents.
		/// </summary>
		/// <returns></returns>
		public double InHoursAsDouble
		{
			get {
				return GetUnits(TimeUnitTypes.Hours);
			}
		}


		/// <summary>
		/// Returns the number of hours this timeunit represents as a string.  Ex.  29h
		/// </summary>
		public string InHoursAsString
		{
			get {
				return (InHoursAsDouble.ToString() + "h");
			}
		}


		/// <summary>
		/// Returns the number of days this TimeUnit represents as a double.
		/// </summary>
		/// <returns></returns>
		public double InDaysAsDouble
		{
			get {
				return GetUnits(TimeUnitTypes.Days);
			}
		}


		/// <summary>
		/// Returns the number of days in string format.  Ex.  16d
		/// </summary>
		public string InDaysAsString
		{
			get {
				return (InDaysAsDouble.ToString() + "d");
			}
		}


		/// <summary>
		/// Returns the number of weeks this TimeUnit represents in double form.  Ex.  6.44
		/// </summary>
		/// <returns></returns>
		public double InWeeksAsDouble
		{
			get {
				return GetUnits(TimeUnitTypes.Weeks);
			}
		}


		/// <summary>
		/// Returns the number of weeks this TimeUnit represents in string form:  6.4w
		/// </summary>
		/// <returns></returns>
		public string InWeeksAsString
		{
			get {
				return (InWeeksAsDouble.ToString() + "w");
			}
		}

		#endregion




		/// <summary>
		/// Returns the proper Unit Type abbreviation (single letter) 
		/// </summary>
		/// <returns>String with single character representing the Unit Type.</returns>
		private string GetUnitTypeAbbrev() {
			switch (unitType) {
				case TimeUnitTypes.Seconds:
					return "s";
				case TimeUnitTypes.Minutes:
					return "m";
				case TimeUnitTypes.Hours:
					return "h";
				case TimeUnitTypes.Days:
					return "d";
				case TimeUnitTypes.Weeks:
					return "w";
				default:
					return "s";
			}
		}



		/// <summary>
		/// Gets the number of units of the Unit Type.  Basically, just converts the internally stored seconds into proper unit value.
		/// </summary>
		/// <returns>double - The number of units of the given UnitType</returns>
		private double GetUnits(TimeUnitTypes tuType) {
			switch (tuType) {
				case TimeUnitTypes.Seconds:
					return _seconds;
				case TimeUnitTypes.Minutes:
					return ConvertSecondsToMinutes(_seconds);
				case TimeUnitTypes.Hours:
					return ConvertSecondsToHours(_seconds);
				case TimeUnitTypes.Days:
					return ConvertSecondsToDays(_seconds);
				case TimeUnitTypes.Weeks:
					return (ConvertSecondsToDays(_seconds) / 7);
				default:
					return _seconds;
			}
		}




		#region To days
		public static double ConvertMillisecondsToDays(double milliseconds) {
			return TimeSpan.FromMilliseconds(milliseconds).TotalDays;
		}

		public static double ConvertSecondsToDays(double seconds) {
			return TimeSpan.FromSeconds(seconds).TotalDays;
		}

		public static double ConvertMinutesToDays(double minutes) {
			return TimeSpan.FromMinutes(minutes).TotalDays;
		}

		public static double ConvertHoursToDays(double hours) {
			return TimeSpan.FromHours(hours).TotalDays;
		}
		#endregion

		#region To hours
		public static double ConvertMillisecondsToHours(double milliseconds) {
			return TimeSpan.FromMilliseconds(milliseconds).TotalHours;
		}

		public static double ConvertSecondsToHours(double seconds) {
			return TimeSpan.FromSeconds(seconds).TotalHours;
		}

		public static double ConvertMinutesToHours(double minutes) {
			return TimeSpan.FromMinutes(minutes).TotalHours;
		}

		public static double ConvertDaysToHours(double days) {
			return TimeSpan.FromHours(days).TotalHours;
		}
		#endregion

		#region To minutes
		public static double ConvertMillisecondsToMinutes(double milliseconds) {
			return TimeSpan.FromMilliseconds(milliseconds).TotalMinutes;
		}

		public static double ConvertSecondsToMinutes(double seconds) {
			return TimeSpan.FromSeconds(seconds).TotalMinutes;
		}

		public static double ConvertHoursToMinutes(double hours) {
			return TimeSpan.FromHours(hours).TotalMinutes;
		}

		public static double ConvertDaysToMinutes(double days) {
			return TimeSpan.FromDays(days).TotalMinutes;
		}
		#endregion

		#region To seconds
		public static double ConvertMillisecondsToSeconds(double milliseconds) {
			return TimeSpan.FromMilliseconds(milliseconds).TotalSeconds;
		}

		public static double ConvertMinutesToSeconds(double minutes) {
			return TimeSpan.FromMinutes(minutes).TotalSeconds;
		}

		public static double ConvertHoursToSeconds(double hours) {
			return TimeSpan.FromHours(hours).TotalSeconds;
		}

		public static double ConvertDaysToSeconds(double days) {
			return TimeSpan.FromDays(days).TotalSeconds;
		}
		#endregion

		#region To milliseconds
		public static double ConvertSecondsToMilliseconds(double seconds) {
			return TimeSpan.FromSeconds(seconds).TotalMilliseconds;
		}

		public static double ConvertMinutesToMilliseconds(double minutes) {
			return TimeSpan.FromMinutes(minutes).TotalMilliseconds;
		}

		public static double ConvertHoursToMilliseconds(double hours) {
			return TimeSpan.FromHours(hours).TotalMilliseconds;
		}

		public static double ConvertDaysToMilliseconds(double days) {
			return TimeSpan.FromDays(days).TotalMilliseconds;
		}
		#endregion
	}
}
